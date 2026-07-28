# fips-shield container: stock nginx plus the shield config and njs
# engine. The image's entrypoint runs envsubst over
# /etc/nginx/templates/*.template into /etc/nginx/conf.d/ at startup,
# substituting only variables that are set in the environment — nginx's
# own $variables pass through. Templates named *.conf.template land in
# the http context, *.stream.template in the stream context (see
# core/nginx/nginx.conf).
#
# Build from the repository root:
#   docker build -f deploy/container/Dockerfile -t fips-shield .

FROM nginx:1.29-alpine

RUN rm /etc/nginx/conf.d/default.conf

COPY core/nginx/nginx.conf /etc/nginx/nginx.conf
COPY core/njs/shield_ws.js /etc/nginx/njs/
COPY core/nginx/00-shield-core.conf.template /etc/nginx/templates/
COPY profiles/strfry/10-strfry.conf.template /etc/nginx/templates/
COPY profiles/strfry/20-strfry-ws.stream.template /etc/nginx/templates/
