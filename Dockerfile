FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sentinel sentinel
ENV SENTINEL_DATA_DIR=/data
VOLUME /data
EXPOSE 8000
CMD ["sh","-c","[ -f /data/model.joblib ] || (python -m sentinel.cli gen && python -m sentinel.cli train); uvicorn sentinel.api:app --host 0.0.0.0 --port 8000"]
