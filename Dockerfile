FROM alpine:3.10

WORKDIR /app

RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*

COPY ./public ./public
COPY ./auth1 auth1

CMD /app/auth1 migration && /app/auth1 server