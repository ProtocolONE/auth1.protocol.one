FROM alpine:3.10

WORKDIR /app

RUN apk --no-cache add tzdata bash ca-certificates mailcap \
 && rm -rf /tmp/* \
 && rm -rf /var/cache/apk/*

COPY ./build/docker/files /
COPY ./public /app/public
COPY ./auth1 auth1

RUN chmod +x /docker/bin/* \
 && chmod +x auth1

#ENTRYPOINT ["/docker/bin/entrypoint.sh"]
ENTRYPOINT /app/auth1 migration && /app/auth1 server