# syntax=docker/dockerfile:1
# Anh Semgrep cho P2 (AI-WhiteSec-CI) - chi nhanh Semgrep, khong co CodeBERT.
# Build (thu muc goc = main/ hoac goc repo co security-config/ va docs/):
#   docker build -f security-config/semgrep/ci/Dockerfile -t aiws-semgrep:4.7.0 .
# Chay:
#   docker run --rm -v <repo>:/src:ro -v <thu muc ket qua>:/out aiws-semgrep:4.7.0 \
#       --repo /src --out /out/semgrep-results.json --scope-out /out/scope.json
# Quyet dinh: QUYET_DINH_SEMGREP.md (GitLab CI, Docker, Semgrep ghim 1.181.0, audit khong chan build).
FROM python:3.11-slim

ARG SEMGREP_VERSION=1.181.0
ENV PYTHONUTF8=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# git: de scan_repo.py doc ma commit cua repo duoc quet (khi chay ngoai GitLab CI)
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/* \
 && git config --system --add safe.directory '*'

RUN pip install "semgrep==${SEMGREP_VERSION}" "pyyaml==6.0.2"

WORKDIR /opt/aiws
# Bo rule da dong goi + nguon rule (verify so bundle voi rules/) + chuan chung taxonomy
COPY docs/taxonomy.yml docs/taxonomy.yml
COPY security-config/semgrep/semgrep.yml \
     security-config/semgrep/ruleset-manifest.json \
     security-config/semgrep/.semgrepignore \
     security-config/semgrep/
COPY security-config/semgrep/rules/ security-config/semgrep/rules/
COPY security-config/semgrep/tools/ruleset.py \
     security-config/semgrep/tools/scan_repo.py \
     security-config/semgrep/tools/

# Anh chi build duoc khi dung phien ban Semgrep va bundle khop manifest (K02 / semgrep_tool.md 2.2 buoc 2)
RUN test "$(semgrep --version 2>/dev/null | tail -n 1)" = "${SEMGREP_VERSION}" \
 && python security-config/semgrep/tools/ruleset.py verify

# File chep tu Windows/tar co the mang quyen 700 -> user scanner khong doc duoc
RUN chmod -R a+rX /opt/aiws \
 && useradd --create-home --uid 10001 scanner
USER scanner
WORKDIR /src

# Ma thoat: 0 = quet xong (Gate quyet dinh), 2 = loi cau hinh/moi truong SAST, 3 = Semgrep loi khi quet
ENTRYPOINT ["python", "/opt/aiws/security-config/semgrep/tools/scan_repo.py"]
CMD ["--repo", "/src", "--out", "/src/semgrep-results.json", "--scope-out", "/src/scope.json"]
