FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml .
COPY scanner ./scanner
COPY templates ./templates
COPY config.yaml .

RUN pip install -e .

ENTRYPOINT ["python", "-m", "scanner.cli"]