FROM python:3.14-alpine

RUN apk add --no-cache wireguard-tools-wg iproute2 nftables

RUN pip install --no-cache-dir prometheus-client

COPY ./src/mesh /app/mesh

WORKDIR /app

CMD ["python", "-m", "mesh", "--config", "/app/config.json", "-v"]
