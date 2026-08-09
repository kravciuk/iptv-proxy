# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py providers_store.py .

# config.py НАМЕРЕННО не копируется в образ. Он содержит список провайдеров
# и всегда монтируется как volume в docker-compose.yml - это даёт
# возможность добавлять/менять провайдеров и порт правкой одного файла на
# хосте, без пересборки образа (нужен только restart контейнера).

ARG IPTV_PROXY_PORT=1200
ENV IPTV_PROXY_PORT=${IPTV_PROXY_PORT}
EXPOSE ${IPTV_PROXY_PORT}

CMD ["python", "server.py"]
