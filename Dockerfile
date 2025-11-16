# Use Python 3.11 slim image for smaller size
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=codea_auth_server.settings

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip --root-user-action=ignore && \
    pip install --no-cache-dir -r requirements.txt --root-user-action=ignore

# Copy project files
COPY . .

# Create logs directory
RUN mkdir -p /app/logs

# Collect static files (if needed)
# RUN python manage.py collectstatic --noinput

# Expose port (Render uses dynamic PORT, default to 8000)
EXPOSE ${PORT:-8000}

# Use entrypoint script
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]

# Default command - use PORT env var for Render compatibility
CMD sh -c "gunicorn codea_auth_server.wsgi:application --bind 0.0.0.0:${PORT:-8000} --workers 4"

