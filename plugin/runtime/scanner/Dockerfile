FROM python:3.13-slim
WORKDIR /scanner
COPY protocol/ ./protocol/
COPY src/ ./src/
ENV PYTHONPATH=/scanner/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65532:65532
ENTRYPOINT ["python", "-m", "bypass_scanner"]
