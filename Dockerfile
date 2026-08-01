FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY seed_files.sh .
RUN chmod +x seed_files.sh && ./seed_files.sh

EXPOSE 8000
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8000", "--timeout", "30", "app:app"]
