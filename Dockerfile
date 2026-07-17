# Shared image for the AEGIS gateway and the async anomaly worker.
# The two services run the same code with different commands (see docker-compose.yml).
FROM python:3.12-slim

WORKDIR /app

# Install deps first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# Default command runs the gateway; the worker overrides this in compose.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
