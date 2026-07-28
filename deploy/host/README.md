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
