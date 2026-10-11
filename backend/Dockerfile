FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl && rm -rf /var/lib/apt/lists/*

# Build context is the project root — no ../ needed
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent ./agent
COPY backend ./backend
COPY dashboard ./dashboard

EXPOSE 8000
# Fix Bug 4: --reload causes restart loops when ./agent is volume-mounted and
# the agent writes state files. Use --workers 1 for single-process stability.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
