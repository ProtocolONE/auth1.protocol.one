FROM golang:1.11.1-alpine AS builder

RUN apk add bash ca-certificates git

WORKDIR /application

ENV GO111MODULE=on

COPY go.mod go.sum ./
RUN go mod download

# Copy all files in currend directiry into home directory
COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -o ./bin/auth1_auth .

FROM alpine:3.9
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
WORKDIR /application
COPY --from=builder /application /application

ENTRYPOINT /application/bin/auth1_auth server -c etc/config.yaml