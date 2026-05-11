FROM nginx:1.27-alpine

RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html

EXPOSE 80
# (Healthcheck handled externally by Traefik via the /healthz route in nginx.conf;
# in-image HEALTHCHECK with no start-period races nginx startup under swarm.)
