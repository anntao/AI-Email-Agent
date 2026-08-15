FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY agent/ ./agent/

RUN useradd --create-home --uid 1000 agent && chown -R agent:agent /app
USER agent

CMD exec gunicorn --bind 0.0.0.0:${PORT} --workers 1 --threads 8 --timeout 120 main:app
