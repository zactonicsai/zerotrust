FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .

# Non-root user for security
RUN useradd -m -u 1000 appuser
USER appuser

EXPOSE 5002

CMD ["python", "app.py"]
