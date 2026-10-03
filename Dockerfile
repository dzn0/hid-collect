# syntax=docker/dockerfile:1
#
# hid-collect — stripped-down collector for Windows kernel drivers shipped with
# HID peripherals, pulled from touslesdrivers.com. Does only collection,
# extraction and content-addressed storage of .sys files. No signature
# verification, no fingerprint, no scope profiles, no analyze stage.
#
#   docker build -t hid-collect:latest .
#   docker compose run --rm collect
#
# Stdlib-only Python; the only non-trivial runtime dep is 7-Zip (archive +
# installer extraction) and curl (fallback downloader when urllib fails).

FROM python:3.13-slim-bookworm

ARG WITH_PLAYWRIGHT=0

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        p7zip-full curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Playwright + Chromium: optional, controlled by WITH_PLAYWRIGHT=1 at build time.
# Needed only when driving the msupdate-catalog paginator through a real browser
# (PDT_MSC_MAX_PAGES > 1). Default off keeps the image lean (~130MB vs ~1GB).
# `playwright install --with-deps chromium` grabs ~190MB of browser plus a bunch
# of apt libs (libxkbcommon, libnss3, libdrm, mesa, fonts); pip install adds the
# Python module.
RUN if [ "$WITH_PLAYWRIGHT" = "1" ]; then \
      pip install --no-cache-dir "playwright>=1.47" \
      && playwright install --with-deps chromium \
      && apt-get clean && rm -rf /var/lib/apt/lists/*; \
    fi

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8

WORKDIR /work
COPY . /work

# Fail the build early if the import graph is broken.
RUN python -m pipeline.collect --list >/dev/null && echo "pipeline imports OK"

ENTRYPOINT ["python", "-m"]
CMD ["pipeline.collect", "--list"]
