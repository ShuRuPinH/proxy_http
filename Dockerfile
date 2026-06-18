# --- build stage ---
FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY . .

# Сборка из vendor — без обращения к сети.
# Статический бинарь без CGO -> чистый Go-резолвер, работает на scratch.
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath -ldflags="-s -w" -o /proxy .

# Готовим каталог для данных с нужным владельцем (наследуется volume'ом).
RUN mkdir -p /data && chown -R 10001:10001 /data

# --- runtime stage ---
FROM scratch

# CA-сертификаты для исходящих HTTPS-апстримов (absolute-form HTTP-запросы).
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /proxy /proxy
COPY --from=builder --chown=10001:10001 /data /data

USER 10001:10001

ENV PROXY_ADDR=:3128 \
    ADMIN_ADDR=:8081 \
    PROXY_CONFIG=/data/config.json

EXPOSE 3128 8081

ENTRYPOINT ["/proxy"]
