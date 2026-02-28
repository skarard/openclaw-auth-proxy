FROM golang:1.24-alpine AS build
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
