#!/usr/bin/env python3
"""
Tests for splitproxy bug fixes.

Verifies:
  Bug 2 - Idle relay timeout (zombie reaping)
  Bug 1 - Sibling reader EOF + wait_closed (FD leak fix)
  Gap 1 - getaddrinfo timeout/fallback (thread pool starvation fix)
  Bug 3 - DNS cache prune (memory leak fix)
  Bug 4 - Refresher self-heal (fire-and-forget fix)

No external dependencies — uses only stdlib (unittest + asyncio).
"""
import asyncio
import os
import socket
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from splitproxy import Config, Proxy, Resolver, DNSError, VPN, DIRECT


# --------------------------------------------------------------------------- helpers

def make_cfg(relay_idle_timeout=0.3, refresh_secs=0.1):
    cfg = Config()
    cfg.relay_idle_timeout = relay_idle_timeout
    cfg.refresh_secs = refresh_secs
    return cfg


async def sock_to_streams(sock):
    """Create asyncio StreamReader/StreamWriter from an already-connected socket."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.create_connection(lambda: protocol, sock=sock)
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    return reader, writer


async def make_relay_ends():
    """Create two socketpairs and return streams for relay testing.

    Returns (r1, w1, r2, w2, br, bw, sr, sw) where:
      r1, w1 — proxy's side of the browser connection
      r2, w2 — proxy's side of the server connection
      br, bw — browser-side streams (write here to send data through the relay)
      sr, sw — server-side streams
    """
    s_browser, s_proxy1 = socket.socketpair()
    s_proxy2, s_server = socket.socketpair()
    for s in (s_browser, s_proxy1, s_proxy2, s_server):
        s.setblocking(False)
    r1, w1 = await sock_to_streams(s_proxy1)
    r2, w2 = await sock_to_streams(s_proxy2)
    br, bw = await sock_to_streams(s_browser)
    sr, sw = await sock_to_streams(s_server)
    return r1, w1, r2, w2, br, bw, sr, sw


async def close_streams(*writers):
    for w in writers:
        try:
            w.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- Bug 2: idle timeout

class TestRelayIdleTimeout(unittest.TestCase):
    """Bug 2: An idle relay should time out, not hang forever."""

    def test_idle_relay_times_out(self):
        """With no data flowing, relay should complete within ~relay_idle_timeout,
        not hang indefinitely."""
        async def run():
            cfg = make_cfg(relay_idle_timeout=0.3)
            proxy = Proxy(cfg)
            r1, w1, r2, w2, br, bw, sr, sw = await make_relay_ends()
            try:
                start = time.monotonic()
                await asyncio.wait_for(proxy.relay(r1, w1, r2, w2), 5)
                elapsed = time.monotonic() - start
                self.assertLess(elapsed, 2.0,
                                f"relay took {elapsed:.1f}s — idle timeout not firing (expected ~0.3s)")
                self.assertEqual(proxy.active, 0, "active count should return to 0 after relay")
            finally:
                await close_streams(bw, sw)
        asyncio.run(run())

    def test_relay_does_not_hang_forever(self):
        """Without the idle timeout fix, this test would hit the 5s test timeout
        instead of completing at ~0.3s."""
        async def run():
            cfg = make_cfg(relay_idle_timeout=0.5)
            proxy = Proxy(cfg)
            r1, w1, r2, w2, br, bw, sr, sw = await make_relay_ends()
            try:
                await asyncio.wait_for(proxy.relay(r1, w1, r2, w2), 3)
                # If we get here, the relay completed — idle timeout worked.
                # If it hung, asyncio.wait_for would have raised TimeoutError.
            finally:
                await close_streams(bw, sw)
        asyncio.run(run())


# --------------------------------------------------------------------------- Bug 1: sibling EOF + wait_closed

class TestSiblingReaderEOF(unittest.TestCase):
    """Bug 1: When one _pipe finishes, the sibling reader should get EOF so the
    other _pipe unblocks immediately instead of waiting for idle timeout."""

    def test_sibling_gets_eof_quickly(self):
        """Browser sends data then closes write side. The server-side reader
        should get EOF via feed_eof() within ~0.2s, not wait for the 10s idle timeout."""
        async def run():
            cfg = make_cfg(relay_idle_timeout=10)  # long — so we know EOF is from sibling
            proxy = Proxy(cfg)
            r1, w1, r2, w2, br, bw, sr, sw = await make_relay_ends()
            try:
                relay_task = asyncio.create_task(proxy.relay(r1, w1, r2, w2))

                # Browser sends some data then EOF
                bw.write(b"hello")
                await bw.drain()
                await asyncio.sleep(0.1)
                bw.write_eof()

                start = time.monotonic()
                await asyncio.wait_for(relay_task, 3)
                elapsed = time.monotonic() - start
                self.assertLess(elapsed, 2.0,
                                f"relay took {elapsed:.1f}s — sibling feed_eof not working (expected <0.5s)")
            finally:
                await close_streams(bw, sw)
        asyncio.run(run())

    def test_data_flows_through_relay(self):
        """Verify data actually flows through the relay in both directions before
        the sibling EOF kicks in."""
        async def run():
            cfg = make_cfg(relay_idle_timeout=5)
            proxy = Proxy(cfg)
            r1, w1, r2, w2, br, bw, sr, sw = await make_relay_ends()
            try:
                relay_task = asyncio.create_task(proxy.relay(r1, w1, r2, w2))

                # Browser -> server
                bw.write(b"ping")
                await bw.drain()

                # Server should receive "ping"
                data = await asyncio.wait_for(sr.read(4), 2)
                self.assertEqual(data, b"ping", "data should flow browser -> server")

                # Server -> browser
                sw.write(b"pong")
                await sw.drain()

                # Browser should receive "pong"
                data = await asyncio.wait_for(br.read(4), 2)
                self.assertEqual(data, b"pong", "data should flow server -> browser")

                # Close browser write side -> relay should end via sibling EOF
                bw.write_eof()
                await asyncio.wait_for(relay_task, 3)
            finally:
                await close_streams(bw, sw)
        asyncio.run(run())


class TestRelayWaitClosed(unittest.TestCase):
    """Bug 1: relay() should call await w.wait_closed() on both writers."""

    def test_wait_closed_called_on_both_writers(self):
        """After relay completes, wait_closed should have been called on both w1 and w2."""
        async def run():
            cfg = make_cfg(relay_idle_timeout=0.3)
            proxy = Proxy(cfg)
            r1, w1, r2, w2, br, bw, sr, sw = await make_relay_ends()

            # Wrap wait_closed to track calls
            w1_called, w2_called = [], []
            orig_w1 = w1.wait_closed
            orig_w2 = w2.wait_closed

            async def track_w1():
                w1_called.append(True)
                await orig_w1()

            async def track_w2():
                w2_called.append(True)
                await orig_w2()

            w1.wait_closed = track_w1
            w2.wait_closed = track_w2

            try:
                await asyncio.wait_for(proxy.relay(r1, w1, r2, w2), 5)
                self.assertTrue(w1_called, "w1.wait_closed() was never called")
                self.assertTrue(w2_called, "w2.wait_closed() was never called")
            finally:
                await close_streams(bw, sw)
        asyncio.run(run())


# --------------------------------------------------------------------------- Gap 1: getaddrinfo timeout

class TestDNSGetaddrinfoFallback(unittest.TestCase):
    """Gap 1: The getaddrinfo fallback must have a timeout and raise DNSError on failure."""

    def _make_resolver(self):
        state = MagicMock()
        state.for_route.return_value = ("en0", 5, [])  # empty servers → skip custom DNS
        return Resolver(state)

    def test_gaierror_raises_dnserro(self):
        """If getaddrinfo raises gaierror, resolve() should raise DNSError."""
        async def run():
            resolver = self._make_resolver()
            loop = asyncio.get_running_loop()
            original = loop.getaddrinfo

            async def mock_gaierror(*a, **kw):
                raise socket.gaierror("mock DNS failure")

            loop.getaddrinfo = mock_gaierror
            try:
                with self.assertRaises(DNSError):
                    await resolver.resolve("nonexistent.example.com", VPN)
            finally:
                loop.getaddrinfo = original
        asyncio.run(run())

    def test_timeout_error_raises_dnserro(self):
        """If the getaddrinfo coroutine is cancelled by wait_for's 10s timeout,
        asyncio.TimeoutError is raised — it must be caught and converted to DNSError.

        We simulate this by making getaddrinfo raise asyncio.TimeoutError directly
        (which is what wait_for does internally on timeout)."""
        async def run():
            resolver = self._make_resolver()
            loop = asyncio.get_running_loop()
            original = loop.getaddrinfo

            async def mock_timeout(*a, **kw):
                raise asyncio.TimeoutError()

            loop.getaddrinfo = mock_timeout
            try:
                with self.assertRaises(DNSError):
                    await resolver.resolve("hanging.example.com", VPN)
            finally:
                loop.getaddrinfo = original
        asyncio.run(run())

    def test_successful_getaddrinfo_returns_ips(self):
        """When getaddrinfo succeeds, resolve() should return the IPs."""
        async def run():
            resolver = self._make_resolver()
            loop = asyncio.get_running_loop()
            original = loop.getaddrinfo

            async def mock_resolve(host, *a, **kw):
                # Simulate a successful getaddrinfo response
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

            loop.getaddrinfo = mock_resolve
            try:
                ips = await resolver.resolve("example.com", VPN)
                self.assertEqual(ips, ["93.184.216.34"])
            finally:
                loop.getaddrinfo = original
        asyncio.run(run())


# --------------------------------------------------------------------------- Bug 3: DNS cache prune

class TestDNSCachePrune(unittest.TestCase):
    """Bug 3: Resolver.cache should evict expired entries periodically."""

    def test_prune_removes_expired_entries(self):
        """Expired entries should be removed; fresh entries should remain."""
        state = MagicMock()
        resolver = Resolver(state)
        now = time.time()

        resolver.cache[("old.com", VPN)] = (["1.1.1.1"], now - 100)
        resolver.cache[("new.com", VPN)] = (["2.2.2.2"], now + 100)
        resolver.cache[("expired.com", DIRECT)] = (["3.3.3.3"], now - 1)
        resolver.cache[("fresh.com", DIRECT)] = (["4.4.4.4"], now + 50)

        resolver._last_prune = 0  # force prune
        resolver._prune()

        self.assertNotIn(("old.com", VPN), resolver.cache, "expired entry should be pruned")
        self.assertNotIn(("expired.com", DIRECT), resolver.cache, "expired entry should be pruned")
        self.assertIn(("new.com", VPN), resolver.cache, "fresh entry should remain")
        self.assertIn(("fresh.com", DIRECT), resolver.cache, "fresh entry should remain")

    def test_prune_60s_gate_prevents_frequent_scans(self):
        """Prune should not run if it ran less than 60 seconds ago."""
        state = MagicMock()
        resolver = Resolver(state)
        now = time.time()

        resolver.cache[("old.com", VPN)] = (["1.1.1.1"], now - 100)
        resolver._last_prune = now  # just pruned

        resolver._prune()

        self.assertIn(("old.com", VPN), resolver.cache,
                      "expired entry should remain — prune gated by 60s cooldown")

    def test_prune_runs_on_first_call(self):
        """First call to _prune (last_prune=0) should execute."""
        state = MagicMock()
        resolver = Resolver(state)
        now = time.time()

        resolver.cache[("expired.com", VPN)] = (["1.1.1.1"], now - 1)
        self.assertEqual(resolver._last_prune, 0.0)

        resolver._prune()

        self.assertNotIn(("expired.com", VPN), resolver.cache, "first prune should remove expired")
        self.assertGreater(resolver._last_prune, 0, "last_prune should be updated")

    def test_prune_handles_empty_cache(self):
        """Prune should not crash on an empty cache."""
        state = MagicMock()
        resolver = Resolver(state)
        resolver._last_prune = 0
        resolver._prune()  # should not raise


# --------------------------------------------------------------------------- Bug 4: refresher self-heal

class TestRefresherSelfHeal(unittest.TestCase):
    """Bug 4: The refresher task should self-heal if it crashes."""

    def test_restart_creates_new_task_after_crash(self):
        """_restart_refresher should create a new task when the old one crashed."""
        async def run():
            cfg = make_cfg(refresh_secs=0.05)
            proxy = Proxy(cfg)

            # Create a task that crashes
            async def crash():
                raise RuntimeError("simulated crash")

            task = asyncio.create_task(crash())
            try:
                await task  # let it complete with exception
            except RuntimeError:
                pass

            # _restart_refresher should create a new task
            proxy._restart_refresher(task)

            self.assertTrue(hasattr(proxy, "_refresher_task"), "new task should be stored")
            self.assertIsNotNone(proxy._refresher_task, "new task should not be None")
            self.assertFalse(proxy._refresher_task.done(), "new task should be running")

            # Clean up
            proxy._refresher_task.cancel()
            try:
                await proxy._refresher_task
            except asyncio.CancelledError:
                pass
        asyncio.run(run())

    def test_restart_does_not_create_task_if_cancelled(self):
        """_restart_refresher should return early if the task was cancelled."""
        async def run():
            cfg = make_cfg(refresh_secs=0.05)
            proxy = Proxy(cfg)

            async def sleeper():
                await asyncio.sleep(100)

            task = asyncio.create_task(sleeper())
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            proxy._restart_refresher(task)

            self.assertFalse(hasattr(proxy, "_refresher_task"),
                             "should not create new task for cancelled task")
        asyncio.run(run())

    def test_new_task_has_self_heal_callback(self):
        """The new task created by _restart_refresher should itself have the
        done-callback attached, so self-healing is recursive."""
        async def run():
            cfg = make_cfg(refresh_secs=0.05)
            proxy = Proxy(cfg)

            async def crash():
                raise RuntimeError("first crash")

            task = asyncio.create_task(crash())
            try:
                await task
            except RuntimeError:
                pass

            proxy._restart_refresher(task)
            new_task = proxy._refresher_task

            # Check that the new task has done-callbacks
            self.assertTrue(len(new_task._callbacks) > 0,
                            "new task should have done-callback for self-healing")

            new_task.cancel()
            try:
                await new_task
            except asyncio.CancelledError:
                pass
        asyncio.run(run())


# --------------------------------------------------------------------------- config

class TestRelayIdleTimeoutConfig(unittest.TestCase):
    """Verify RELAY_IDLE_TIMEOUT config is read from env."""

    def test_default_value(self):
        """Default relay_idle_timeout should be 300."""
        os.environ.pop("RELAY_IDLE_TIMEOUT", None)
        cfg = Config()
        self.assertEqual(cfg.relay_idle_timeout, 300.0)

    def test_env_override(self):
        """RELAY_IDLE_TIMEOUT env var should override the default."""
        os.environ["RELAY_IDLE_TIMEOUT"] = "42"
        try:
            cfg = Config()
            self.assertEqual(cfg.relay_idle_timeout, 42.0)
        finally:
            os.environ.pop("RELAY_IDLE_TIMEOUT", None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
