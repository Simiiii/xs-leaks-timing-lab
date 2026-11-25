FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml config.py run.py ./
COPY victim/ ./victim/
COPY attacker/ ./attacker/
COPY tests/ ./tests/

EXPOSE 8001 8002

CMD ["python", "-u", "run.py"]
