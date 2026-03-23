FROM debian:bookworm

COPY src/ /app/src
COPY lib /app/lib
COPY tools /app/tools
COPY misc /app/misc
COPY config.json /app/config.json
COPY makefile /app/makefile
COPY python/ /app/python
RUN mkdir /app/www

RUN apt-get update
RUN apt-get -y install make gcc libcurl4-gnutls-dev zlib1g zlib1g-dev build-essential libffi-dev\
    libssl-dev libc6-dev libsqlite3-dev tesseract-ocr tesseract-ocr-pol
WORKDIR /app/python
RUN ./configure \
    && make \
    && make install
WORKDIR /usr/bin
RUN ln -s /app/python/python python
WORKDIR /app
RUN make
WORKDIR /app/tools
#RUN python -m venv venv
RUN python -m pip install chromadb requests
ENTRYPOINT [ "/app/tmp/pika_ml_relay", "-w=1", "-t=8", "-cfg=/app/config.json", "-ping=5", "-llog=1", "-www=/app/www" ]