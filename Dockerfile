# syntax=docker/dockerfile:1
FROM golang:1.27 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION:-dev}" -o /out/ldapact ./cmd/ldapact

FROM gcr.io/distroless/static-debian12
COPY --from=builder /out/ldapact /usr/local/bin/ldapact
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ldapact"]
