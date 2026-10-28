FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ /app/src/
COPY Dockerfile docker-compose.yml ./
RUN useradd -m app && mkdir -p /data && chown -R app /data
USER app
ENV SOVEREIGN_DB=/data/sovereign_audit.db
EXPOSE 8000
CMD ["uvicorn", "sovereignmcp.gateway:app", "--host", "0.0.0.0", "--port", "8000"]
```[cite: 15]