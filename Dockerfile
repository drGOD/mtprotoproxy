FROM python:3.12-slim

RUN apt-get update && apt-get install --no-install-recommends -y \
    libcap2-bin \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN setcap cap_net_bind_service=+ep /usr/local/bin/python3.12

RUN useradd -m tgproxy -u 10000

USER tgproxy

WORKDIR /home/tgproxy/

COPY --chown=tgproxy requirements.txt /home/tgproxy/
RUN python3 -m pip install --no-cache-dir -r /home/tgproxy/requirements.txt

COPY --chown=tgproxy mtprotoproxy.py ui.html /home/tgproxy/

RUN mkdir -p /home/tgproxy/data

CMD ["python3", "mtprotoproxy.py"]
