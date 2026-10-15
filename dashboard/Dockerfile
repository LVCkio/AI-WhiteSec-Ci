FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    HF_HOME=/tmp/huggingface

WORKDIR /app
COPY requirements.txt requirements-model.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 whitesec \
    && useradd --uid 10001 --gid whitesec --no-create-home whitesec
COPY --chown=10001:10001 app ./app
COPY --chown=10001:10001 config ./config

# Gateway owns the merged Security Gate policy; explicit demo inference needs no model dependencies.
FROM base AS runtime
USER 10001:10001
CMD ["python", "-m", "uvicorn", "app.gateway:app", "--host", "0.0.0.0", "--port", "8080"]

# A local, reviewed checkpoint is mounted at runtime; none is downloaded here.
FROM base AS model
RUN python -m pip install --no-cache-dir torch==2.8.0 --index-url https://download.pytorch.org/whl/cpu \
    && python -m pip install --no-cache-dir -r requirements-model.txt
USER 10001:10001
CMD ["python", "-m", "uvicorn", "app.codebert:app", "--host", "0.0.0.0", "--port", "8001"]
