FROM python:3.11.0rc1-slim-bullseye@sha256:129de790b67d34329b0e3fed57d69005d4dbd5a215b4af1ed82c2e306ff50eb3

ADD requirements.txt /tmp/flask-requirements.txt
RUN pip3 install -qr /tmp/flask-requirements.txt
RUN mkdir /code

ENTRYPOINT ["python3", "/code/service.py"]
