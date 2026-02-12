# Async MTProto Proxy #

Fast and simple to setup MTProto proxy written in Python.

## Starting Up ##
    
1. `git clone -b stable https://github.com/alexbers/mtprotoproxy.git; cd mtprotoproxy`
2. Install deps: `python3 -m pip install -r requirements.txt`
3. Run: `python3 mtprotoproxy.py`
4. *(optional, get a link to share the proxy)* `docker-compose logs`

![Demo](https://alexbers.com/mtprotoproxy/install_demo_v2.gif)

## Channel Advertising ##

To advertise a channel get a tag from **@MTProxybot** and set it via REST API (`PUT /config`, field `ad_tag`).

## Performance ##

The proxy performance should be enough to comfortably serve about 4 000 simultaneous users on
the VDS instance with 1 CPU core and 1024MB RAM.

## More Instructions ##

- [Running without Docker](https://github.com/alexbers/mtprotoproxy/wiki/Running-Without-Docker)
- [Optimization and fine tuning](https://github.com/alexbers/mtprotoproxy/wiki/Optimization-and-Fine-Tuning)

## Advanced Usage ##

The proxy can be launched:
- with a custom config: `python3 mtprotoproxy.py [configfile]`
- several times, clients will be automaticaly balanced between instances
- with uvloop module to get an extra speed boost
- with runtime statistics exported to [Prometheus](https://prometheus.io/)

## Config REST API ##

The proxy can run with embedded REST API and store its config in local sqlite.

1. Install deps: `python3 -m pip install -r requirements.txt`
2. Run proxy + API in one process: `python3 mtprotoproxy.py`

By default API listens on `127.0.0.1:8080`.
You can change it using env vars: `MTPROTO_API_HOST`, `MTPROTO_API_PORT`.

Embedded one-page UI is available at `http://127.0.0.1:8080/` (or `/ui`).

Config is stored in `./config.db` by default (env: `MTPROTO_CONFIG_DB`).
Config source can be switched with `MTPROTO_CONFIG_SOURCE` (`db` or `file`).

When you update config via API (`PUT /config`, `/users` endpoints), proxy automatically reloads it.
Changing `PORT` at runtime is not supported and requires restart.
