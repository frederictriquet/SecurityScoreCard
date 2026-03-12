FROM python:3.14-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git openssl procps bsdmainutils dnsutils \
    && rm -rf /var/lib/apt/lists/*

# testssl.sh — outil standalone pour l'analyse TLS avancée
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl
ENV TESTSSL_PATH=/opt/testssl/testssl.sh

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/

RUN mkdir -p /data

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
