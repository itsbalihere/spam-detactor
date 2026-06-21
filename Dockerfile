FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8000
ENV SPAM_DETECTOR_DB=/data/spam_detector.sqlite3

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && mkdir -p /data

COPY . .

EXPOSE 8000

CMD ["sh", "-c", "uvicorn model_copy:app --host 0.0.0.0 --port ${PORT}"]
