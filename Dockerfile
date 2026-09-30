# Small, non-root image for the REST API + approval console.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    OPSWATCH_DB=/app/data/opswatch.db OPSWATCH_TRIAGER=rules

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY config ./config
# Editable install keeps config/ next to the code, where the app looks for it.
RUN pip install --no-cache-dir -e . \
 && useradd --create-home --uid 10001 opswatch \
 && mkdir -p /app/data /app/models /app/reports \
 && chown -R opswatch /app/data /app/models /app/reports
USER opswatch

# Build the dataset and knowledge base into the image so startup is instant.
RUN opswatch seed

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
# OPSWATCH_API_KEY must be provided at runtime:  docker run -e OPSWATCH_API_KEY=... -p 8000:8000 opswatch
CMD ["opswatch", "serve-api", "--host", "0.0.0.0", "--port", "8000"]
