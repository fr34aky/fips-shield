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

```sh
cp shield.env.example shield.env && $EDITOR shield.env
sudo deploy/host/render.sh shield.env
sudo nginx -t && sudo systemctl reload nginx
```

`render.sh` renders every template into `/etc/nginx/conf.d/` (http
stage as `*.conf`, stream stage as `*.stream`) and installs the njs
engine to `/etc/nginx/njs/shield_ws.js`. Pass a second/third argument
to override the output and njs directories.

## Detection engine

```sh
sudo deploy/host/install-fail2ban.sh shield.env
sudo fail2ban-client -t && sudo systemctl reload fail2ban
```

## eBPF guard (optional, Linux only)

Kernel-level enforcement instead of nginx-level: bans cover every
listener on `fips0` and cost nothing per packet. Build and install
per [../../guard/README.md](../../guard/README.md), then:

```sh
sudo install -m 644 deploy/host/fips-guard.service /etc/systemd/system/
printf 'SHIELD_GUARD_IFACE=fips0\n' | sudo tee /etc/default/fips-guard
sudo systemctl enable --now fips-guard
```

With `/usr/local/bin/shield-ban` pointing at the guard wrapper, the
existing fail2ban jails enforce in the kernel with no other changes.
