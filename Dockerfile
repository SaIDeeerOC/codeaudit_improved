# Собирается один раз во внутреннем зеркале; дальше работает без интернета.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git shellcheck curl \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir ruff bandit semgrep
# gitleaks: положить бинарник из внутреннего хранилища
# COPY gitleaks /usr/local/bin/gitleaks
WORKDIR /app
COPY pipeline.py config.toml ./
ENTRYPOINT ["python3", "/app/pipeline.py"]
CMD ["/repo", "--out", "/report", "--config", "/app/config.toml"]
