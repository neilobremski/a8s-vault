ARG BASE=public.ecr.aws/docker/library/python:3.12-slim
FROM ${BASE}
RUN pip install --no-cache-dir paho-mqtt \
 && apt-get update && apt-get install -y --no-install-recommends openssl procps \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --shell /bin/sh vault
ENV PATH=/opt/ar3:$PATH
