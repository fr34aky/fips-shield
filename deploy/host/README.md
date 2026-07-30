# Host mode

nginx runs directly on the fips node. Since Phase 2 the shield is two
nginx stages: a `stream{}` server on the fips0 address doing WebSocket
message inspection (njs), proxying to a loopback `http{}` server doing
handshake limits and filtering.

## Prerequisites

1. nginx with the **njs stream module**:
   - nginx.org packages: `apt install nginx-module-njs` (then add
     `load_module modules/ngx_stream_js_module.so;` at the top of
     `/etc/nginx/nginx.conf`).
   - Debian/Ubuntu distro nginx: `apt install libnginx-mod-stream-js`
     (auto-loaded via `/etc/nginx/modules-enabled/`). If the package is
     not available on your release, use the nginx.org repository.
2. A `stream{}` block in `nginx.conf` that picks up the rendered stream
   configs (the http configs land in `conf.d/*.conf`, which stock
   nginx.conf already includes):

   ```nginx
   stream {
       include /etc/nginx/conf.d/*.stream;
   }
   ```

   `core/nginx/nginx.conf` in this repo is the reference layout (it is
   the config the container ships).

## Install / update

One step for everything host-side — nginx configs, the detection engine,
and optionally the eBPF guard:

```sh
cp shield.env.example shield.env && $EDITOR shield.env
sudo deploy/host/install.sh shield.env        # or: sudo make install
sudo nginx -t && sudo systemctl reload nginx
```

`install.sh` asks about the eBPF guard when the host can run it, and
explains why not when it cannot. Decide up front with `--with-guard` /
`--without-guard`; non-interactively it defaults to no. `--no-nginx`
skips the config rendering, which is the split deployment (nginx in a
container, detection and enforcement here) — see
[../container/compose.split.yaml](../container/compose.split.yaml) and
`make install-split`. `PREFIX` and `F2B_DIR` are honoured, the latter for
FreeBSD's `/usr/local/etc/fail2ban`.

To render only the nginx configs, as before:

```sh
sudo deploy/host/render.sh shield.env
```

It also provisions `SHIELD_SOCKET_DIR` (default `/run/fips-shield`),
the private directory holding the sockets that join each profile's
stream stage to its http stage. That directory must be mode 0700 and
owned by the nginx worker user — nginx makes unix listen sockets
world-connectable, so those permissions are what stop another local
process from connecting and spoofing a client address past the shield.
`/run` is a tmpfs on most systems, so install the tmpfiles snippet to
recreate it at boot:

```sh
sudo install -m 644 deploy/host/fips-shield-tmpfiles.conf \
    /etc/tmpfiles.d/fips-shield.conf
```

`render.sh` renders every template into `/etc/nginx/conf.d/` (http
stage as `*.conf`, stream stage as `*.stream`) and installs the njs
engine to `/etc/nginx/njs/shield_ws.js`. Pass a second/third argument
to override the output and njs directories.

## Detection engine

Already done by `install.sh`; run it on its own to update only the
filters, jails and banaction:

```sh
sudo deploy/host/install-fail2ban.sh shield.env
sudo fail2ban-client -t && sudo systemctl reload fail2ban
```

It installs the banlist-file backend as `shield-ban`, but never over an
existing eBPF wrapper — so re-running it cannot silently downgrade a host
using kernel enforcement. The file backend always lands in
`$PREFIX/lib/fips-shield/shield-ban-file` regardless.

## Log rotation

Only needed when nginx runs in a container and its logs are bind-mounted
here (the split deployment); a host nginx is covered by the distro's own
logrotate snippet.

```sh
sudo install -m 644 deploy/host/fips-shield.logrotate \
    /etc/logrotate.d/fips-shield
```

The `postrotate` hook signals nginx *inside* the container to reopen its
logs. Without it nginx keeps writing to the rotated inode: the live log
stays empty and fail2ban sees nothing.

## eBPF guard (optional, Linux only)

Kernel-level enforcement instead of nginx-level: bans cover every
listener on `fips0` and cost nothing per packet. Build as your normal
user (needs `clang`; see
[../../guard/README.md](../../guard/README.md), including how to build
for a host without clang), then install as root:

```sh
make guard                     # as you — not under sudo
sudo make install-guard        # installs fips-guard + the systemd unit
printf 'SHIELD_GUARD_IFACE=fips0\n' | sudo tee /etc/default/fips-guard
sudo systemctl enable --now fips-guard
```

`sudo deploy/host/install.sh shield.env --with-guard` does the same
(including `/etc/default/fips-guard`) as part of one install; `make guard`
still has to run as your own user first.

`make guard` must run as your own user: with a rustup toolchain, `cargo`
lives in `~/.cargo/bin`, which sudo's `secure_path` excludes.

With `/usr/local/bin/shield-ban` pointing at the guard wrapper, the
existing fail2ban jails enforce in the kernel with no other changes.
