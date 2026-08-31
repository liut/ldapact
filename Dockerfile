# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS builder
WORKDIR /src
# ENV GOPROXY='https://goproxy.cn,https://goproxy.io,direct'  # uncomment for CN networks
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION:-dev}" -o /out/ldapact ./cmd/ldapact

FROM gcr.io/distroless/static-debian13
COPY --from=builder /out/ldapact /usr/local/bin/ldapact
USER nonroot:nonroot
EXPOSE 8389
ENTRYPOINT ["/usr/local/bin/ldapact"]
