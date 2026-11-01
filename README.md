# splitproxy

Per-host split tunnelling for macOS with GlobalProtect in full-tunnel mode.

Keep GlobalProtect connected all the time. Hosts you list in `VPN_HOSTS`
(e.g. `bitbucket.juspay.net`) are reached through the tunnel; everything
else (e.g. `youtube.com`) is sent straight out of your Wi-Fi interface and
never enters the tunnel.

It works by running a local HTTP/HTTPS + SOCKS5 proxy that pins every
outbound socket to a specific interface with the macOS `IP_BOUND_IF`
socket option. That overrides the routing table per connection, so
GlobalProtect's routes are never modified. DNS is split the same way:
VPN hosts resolve via the DNS servers GlobalProtect pushed, direct hosts
resolve via `DIRECT_DNS` over the physical interface.

No dependencies beyond Python 3 (ships with Homebrew / Xcode CLT).

## Install / uninstall (one command)

```sh
./setup.sh install      # login item + keep-alive + system proxy on + self-test
./setup.sh status       # what is installed, is the proxy healthy
./setup.sh test         # re-run the routing self-test
./setup.sh uninstall    # system proxy off, login item removed, proxy stopped
```

`install` touches three things: a runtime copy in `~/.splitproxy`, a LaunchAgent
plist in `~/Library/LaunchAgents`, and the proxy settings of your Wi-Fi network
service. `uninstall` reverts all three.
Routes, DNS and GlobalProtect are never modified.

## Manual / try-before-install

```sh
cp .env.example .env        # edit VPN_HOSTS etc.
./splitproxy.py             # foreground; Ctrl-C to stop
```

Then, in another shell, with GlobalProtect connected:

```sh
curl http://127.0.0.1:8080/status                                  # detected interfaces + rules
curl -I -x http://127.0.0.1:8080 https://bitbucket.juspay.net/     # -> vpn(utunX)
curl -I -x http://127.0.0.1:8080 https://www.youtube.com/          # -> direct(en0)
```

Watch the log: every connection prints `host:port -> vpn(utun4) 10.x.x.x`
or `-> direct(en0) 142.x.x.x`.

## Pointing apps at it

* **Whole system (Safari, Chrome, Slack, most apps):**
  `./sysproxy.sh on` sets the macOS HTTP, HTTPS and SOCKS proxies for your
  active network service. `./sysproxy.sh off` reverts. macOS requires admin
  rights for this, so it runs `networksetup` via `sudo` and asks for your
  password. If your account is not an admin, use the per-app options below.
* **Chrome only (no admin needed):**
  `open -a "Google Chrome" --args --proxy-server=http://127.0.0.1:8080` Firefox uses its own
  proxy settings: Settings > Network > "Use system proxy settings", or the
  PAC URL `http://127.0.0.1:8080/proxy.pac`.
* **Shell / CLI tools:**
  ```sh
  export HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080 ALL_PROXY=socks5h://127.0.0.1:1080
  export NO_PROXY=localhost,127.0.0.1
  ```
* **git over ssh** does not use HTTP proxies. Add to `~/.ssh/config`:
  ```
  Host bitbucket.juspay.net
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
  ```

## Run at login

```sh
./install-launchd.sh            # installs a LaunchAgent with KeepAlive
./install-launchd.sh uninstall
```
macOS does not let launchd run jobs out of `~/Desktop`, `~/Documents` or
`~/Downloads` (they die with exit 78). The installer therefore copies
`splitproxy.py` and `.env` to `~/.splitproxy` and runs from there; logs are in
`~/.splitproxy/logs/splitproxy.log`. Re-run `./install-launchd.sh` (or
`./setup.sh install`) after editing `.env` to copy the new config and restart.

## Configuration (.env)

| Variable        | Default              | Meaning |
|-----------------|----------------------|---------|
| `VPN_HOSTS`     |                      | Hosts forced through the tunnel. `host`, `*.domain`, or CIDR. |
| `DIRECT_HOSTS`  |                      | Hosts forced to bypass the tunnel. |
| `DEFAULT_ROUTE` | `direct`             | Where unmatched hosts go: `direct` or `vpn`. |
| `VPN_IFACE`     | `auto`               | GlobalProtect interface (`utunN`/`gpdN`). Auto re-detected every 5 s. |
| `DIRECT_IFACE`  | `auto`               | Physical interface (`enN`). |
| `VPN_DNS`       | auto from `scutil`   | DNS servers for VPN hosts. |
| `DIRECT_DNS`    | `1.1.1.1,8.8.8.8`    | DNS servers for direct hosts, queried over the physical interface. |
| `HTTP_LISTEN`   | `127.0.0.1:8080`     | HTTP/HTTPS proxy address. |
| `SOCKS_LISTEN`  | `127.0.0.1:1080`     | SOCKS5 proxy address. |
| `LOG_LEVEL`     | `INFO`               | `DEBUG` for handler errors. |

Most-specific rule wins (`bitbucket.juspay.net` beats `*.juspay.net`); on a
tie, VPN wins. Flip `DEFAULT_ROUTE=vpn` and list only the sites you want
outside the tunnel in `DIRECT_HOSTS` if that's the shorter list.

## Caveats

* Only traffic that honours proxy settings is split. Anything that ignores
  them still follows GlobalProtect's routes.
* Some GlobalProtect configurations block traffic that bypasses the tunnel
  while connected. If direct connections fail with GP up but work with GP
  down, that is the gateway policy and only IT can relax it.
* Check that bypassing the tunnel for non-corporate sites is acceptable
  under your company's security policy.
* IPv4 only for the direct DNS path; AAAA records are not queried.
