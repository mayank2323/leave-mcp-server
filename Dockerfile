FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY combined_server.py .

CMD uvicorn combined_server:app --host 0.0.0.0 --port ${PORT:-8080}
