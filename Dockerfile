# Incident Analyst の画像。2 段階。
# 依存は uv.lock から書き出した deploy/requirements.txt（ハッシュ付き）で入れ、本体は tools/image-build.sh が
# 手元で作った wheel（deploy/dist/）を --no-deps で入れる。ビルドの道具は最終の画像に残らない。
FROM python:3.13-slim@sha256:bf44cdfcb76cd3b41e879bc058fc37ec5872002ccfde7fcb765e218cde0cd79c AS build
WORKDIR /src
COPY deploy/requirements.txt ./
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes -r requirements.txt
COPY deploy/dist/tia-*.whl ./
RUN /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check --no-deps tia-*.whl \
 && /opt/venv/bin/python -m compileall -q /opt/venv/lib

FROM python:3.13-slim@sha256:bf44cdfcb76cd3b41e879bc058fc37ec5872002ccfde7fcb765e218cde0cd79c
# 確認は ssh の実行ファイルで VM に入る。実行時に要る唯一の OS の道具
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends openssh-client >/dev/null \
 && rm -rf /var/lib/apt/lists/*
# 動かす利用者は uid と gid が 10001。/data と /backups だけに書く
RUN groupadd --gid 10001 analyzer \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin analyzer \
 && mkdir -p /data /backups /config \
 && chown 10001:10001 /data /backups
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Asia/Tokyo
USER 10001:10001
WORKDIR /data
EXPOSE 8000
# 生きているかだけを見る。/healthz の 503 は「準備中」で、Uptime Kuma が状態コードで見る
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.error, urllib.request\ntry:\n    urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)\nexcept urllib.error.HTTPError:\n    pass\nexcept Exception:\n    sys.exit(1)\n"]
ENTRYPOINT ["tia"]
CMD ["run", "--db", "/data/tia.sqlite", "--config", "/config/analyzer.yaml", "--type-rules", "/config/type-rules.yaml", "--knowledge", "/config/knowledge", "--config-dir", "/config"]
