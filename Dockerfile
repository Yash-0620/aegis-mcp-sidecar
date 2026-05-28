FROM python:3.11-slim

WORKDIR /app

# 1. Install all dependencies, explicitly including cryptography
RUN pip install fastapi uvicorn httpx aegis-aip PyJWT==2.10.1 cryptography

# 2. Copy the proxy logic
COPY sidecar_proxy.py .

# 3. Expose the port
EXPOSE 8080

# 4. FIX: Boot the Uvicorn server to keep the process alive and listening
CMD ["uvicorn", "sidecar_proxy:app", "--host", "0.0.0.0", "--port", "8080"]
