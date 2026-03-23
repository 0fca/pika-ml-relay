FROM python:3.13-bookworm

COPY src/ /app/src
COPY lib /app/lib
COPY tools /app/tools
COPY misc /app/misc
COPY config.json /app/config.json
COPY makefile /app/makefile
RUN mkdir /app/www

RUN apt-get update
RUN apt-get -y install make gcc libcurl4-gnutls-dev zlib1g zlib1g-dev build-essential libffi-dev\
    libssl-dev libc6-dev libsqlite3-dev tesseract-ocr tesseract-ocr-pol
WORKDIR /app
RUN make
WORKDIR /app/tools
RUN pip install chromadb requests
ENTRYPOINT [ "/app/tmp/pika_ml_relay", "-w=2", "-t=8", "-cfg=/app/config.json", "-ping=5", "-llog=1", "-www=/app/www" ]