FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY README.md pyproject.toml requirements.txt setup.py server.py /app/
COPY src /app/src

RUN python -m pip install --no-cache-dir .

EXPOSE 8080

CMD ["google-mcp-server"]
