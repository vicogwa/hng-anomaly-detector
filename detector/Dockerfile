FROM python:3.11-slim

WORKDIR /app

# Install iptables — required for IP blocking
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create audit log directory
RUN mkdir -p /var/log/detector

CMD ["python", "main.py"]