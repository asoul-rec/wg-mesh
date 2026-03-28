FROM python:3.14-alpine

RUN apk add --no-cache wireguard-tools-wg

WORKDIR /app
CMD ["python", "-m", "src.mesh", "--config", "/app/config.json"]
