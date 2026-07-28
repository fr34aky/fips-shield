# fips-shield container: stock nginx plus the shield templates. The
# image's entrypoint runs envsubst over /etc/nginx/templates/*.template
# into /etc/nginx/conf.d/ at startup, substituting only variables that
# are set in the environment — nginx's own $variables pass through.
#
# Build from the repository root:
#   docker build -f deploy/container/Dockerfile -t fips-shield .

FROM nginx:1.29-alpine

RUN rm /etc/nginx/conf.d/default.conf

COPY core/nginx/00-shield-core.conf.template /etc/nginx/templates/
COPY profiles/strfry/10-strfry.conf.template /etc/nginx/templates/
