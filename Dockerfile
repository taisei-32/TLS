FROM golang:1.23-alpine AS builder

WORKDIR /app/

COPY . .
RUN go build -trimpath -ldflags "-w -s" -o app ./cmd
# ---------------------------------------------------
FROM debian:bullseye-slim AS deploy

COPY --from=builder /app/app .

ENTRYPOINT ["./app"]