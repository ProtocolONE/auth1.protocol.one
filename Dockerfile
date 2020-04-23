FROM golang:1.13-alpine AS builder

RUN apk add bash ca-certificates git
WORKDIR /app

COPY go.mod.cache go.mod
RUN go mod download

COPY go.mod go.sum ./
RUN go mod download

# Copy all files in currend directiry into home directory
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -o ./auth1 .


# PRODUCTION IMAGE
FROM alpine:3.10

WORKDIR /app

RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*

COPY --from=builder /app/auth1 auth1
COPY --from=builder /app/public public

CMD /app/auth1 migration && /app/auth1 server