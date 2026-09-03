FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/issuer ./cmd/issuer

FROM scratch
COPY --from=build /out/issuer /issuer
EXPOSE 8080
ENTRYPOINT ["/issuer"]
