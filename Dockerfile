FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/issuer ./cmd/issuer

FROM scratch
# Needed for outbound HTTPS (attestation-registry, and optionally the
# Fikua DSS) — unlike fikua-lab-attestation-registry, this service makes
# outbound TLS calls, so it can't skip CA certs the way that one does.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/issuer /issuer
EXPOSE 8080
ENTRYPOINT ["/issuer"]
