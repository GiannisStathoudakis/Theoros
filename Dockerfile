FROM golang:1.26.5-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o theoros-server ./cmd/server/main.go

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /app/theoros-server .

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/theoros-server"]