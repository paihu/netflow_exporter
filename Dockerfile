# syntax=docker/dockerfile:1
FROM golang:1.22.0-alpine3.19 AS builder

RUN addgroup -S appgroup && adduser -S appuser -G appgroup -u 1001

WORKDIR /
COPY go.mod ./
COPY go.sum ./
COPY *.go ./

RUN go mod download
RUN go build -o ./app

FROM scratch
LABEL authors="paihu"

COPY --from=builder /etc/passwd /etc/passwd
USER 1001

COPY --from=builder /app /app

EXPOSE 2055/udp
EXPOSE 9191/tcp

ENTRYPOINT [ "/app" ]
