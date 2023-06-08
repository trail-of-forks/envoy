FROM python:3.11.4-slim-bullseye@sha256:1966141ab594e175852a033da2a38f0cb042b5b92896c22073f8477f96f43b06

ENV DEBIAN_FRONTEND=noninteractive

ADD requirements.txt /tmp/flask-requirements.txt
RUN pip3 install -qr /tmp/flask-requirements.txt \
    && apt-get update \
    && apt-get install -y -qq --no-install-recommends netcat \
    && apt-get -qq autoremove -y \
    && apt-get clean \
    && rm -rf /tmp/* /var/tmp/* \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /code

HEALTHCHECK \
    --interval=1s \
    --timeout=1s \
    --start-period=1s \
    --retries=3 \
    CMD nc -zv localhost 8080

ENTRYPOINT ["python3", "/code/service.py"]
