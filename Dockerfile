FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install fastapi uvicorn httpx aegis-aip

# Copy the proxy logic
COPY sidecar_proxy.py .

# Expose the Sidecar port (8080)
EXPOSE 8080

# Run the proxy
CMD ["python", "sidecar_proxy.py"]