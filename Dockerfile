FROM python:3.12-slim
WORKDIR /app
COPY backend/server.py /app/server.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080
EXPOSE 8080
CMD ["python","server.py"]
