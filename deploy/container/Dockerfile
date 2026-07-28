# fips-shield container: stock nginx plus the shield config, the njs
# engine, and every profile. SHIELD_PROFILES selects which profiles are
# staged at startup; the stock entrypoint then runs envsubst over
# /etc/nginx/templates/*.template into /etc/nginx/conf.d/, substituting
# only variables set in the environment — nginx's own $variables pass
# through. Templates named *.conf.template land in the http context,
# *.stream.template in the stream context (see core/nginx/nginx.conf).
#
# Build from the repository root:
#   docker build -f deploy/container/Dockerfile -t fips-shield .

FROM nginx:1.29-alpine

RUN rm /etc/nginx/conf.d/default.conf

COPY core/nginx/nginx.conf /etc/nginx/nginx.conf
COPY core/njs/ /etc/nginx/njs/
COPY core/nginx/*.template /etc/nginx/templates/
COPY profiles/ /etc/nginx/profiles/
COPY deploy/container/shield-entrypoint.sh /shield-entrypoint.sh
RUN chmod +x /shield-entrypoint.sh

ENTRYPOINT ["/shield-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
