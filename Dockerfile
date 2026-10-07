# syntax=docker/dockerfile:1
#
# hid-driver-triage — stripped-down collector for Windows kernel drivers shipped with
# HID peripherals, pulled from the Microsoft Update Catalog (WHQL-signed). Does
# only collection, extraction and content-addressed storage of .sys files. No
# signature verification, no fingerprint, no scope profiles, no analyze stage.
#
#   docker build -t hid-driver-triage:latest .
#   docker compose run --rm msupdate-catalog
#
# Mostly stdlib Python. Runtime deps: 7-Zip (archive + installer extraction),
# curl + curl_cffi (streaming downloads), aria2 (BitTorrent client for the
# snappy-driver collector — installed here, never expected on the host), and
# Playwright/Chromium — the MS catalog paginates via an ASP.NET postback that
# stdlib urllib cannot follow, so discovery always drives a real headless browser.

FROM python:3.13-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        p7zip-full curl ca-certificates aria2 \
 && rm -rf /var/lib/apt/lists/*

# curl_cffi: TLS/JA3 impersonation for streaming downloads. Ships a prebuilt
# manylinux wheel with libcurl-impersonate bundled — no extra apt deps.
# playwright: drives headless Chromium for catalog search pagination.
RUN pip install --no-cache-dir "curl_cffi>=0.7" "playwright>=1.44"

# Install the Chromium build plus its OS library dependencies. `--with-deps`
# pulls the needed apt packages; this is the heaviest layer in the image.
RUN playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

WORKDIR /work
COPY . /work

# Fail the build early if the import graph is broken.
RUN python -m pipeline.collect --list >/dev/null && echo "pipeline imports OK"

ENTRYPOINT ["python", "-m"]
CMD ["pipeline.collect", "--list"]
