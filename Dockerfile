FROM python:3.12-slim
RUN apt-get update && apt-get install -y iputils-ping
COPY scanner.py scanner.py
CMD ["python3", "scanner.py"]
