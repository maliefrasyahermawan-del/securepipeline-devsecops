# INTENTIONAL: running as root (no USER directive) — Trivy config scan will flag this
# INTENTIONAL: no HEALTHCHECK directive — Trivy config scan will flag this
# Both are intentional for DevSecOps pipeline demo purposes

FROM python:3.11-slim

WORKDIR /app

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

ENV PYTHONPATH=/app
ENV DB_PATH=/app/users.db

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
