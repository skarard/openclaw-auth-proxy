FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /auth-proxy ./cmd/auth-proxy

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /auth-proxy /usr/local/bin/auth-proxy
ENTRYPOINT ["auth-proxy"]
CMD ["--config", "/etc/auth-proxy/config.yaml"]

# To bake the proxy CA into agent containers (for TLS MITM):
#
# 1. Generate the CA:
#    docker run --rm -v /tmp/certs:/output auth-proxy --generate-ca --cert-dir /output/
#
# 2. In agent container Dockerfile:
#    COPY ca.crt /usr/local/share/ca-certificates/auth-proxy-ca.crt
#    RUN update-ca-certificates
