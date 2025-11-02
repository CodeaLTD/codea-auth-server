#!/bin/bash
set -e

# Check if migrations are needed
echo "Checking for pending migrations..."
if python manage.py showmigrations 2>/dev/null | grep -q "\\[ \\]"; then
    echo "Pending migrations found, applying migrations..."
    python manage.py migrate --noinput
    echo "Migrations applied successfully."
else
    echo "All migrations are up to date, skipping migration step."
fi

echo "Collecting static files..."
python manage.py collectstatic --noinput || true

echo "Starting server..."
exec "$@"
