FROM python:3.12-slim
RUN apt-get update && apt-get install -y iputils-ping
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY scanner.py scanner.py
COPY app.py app.py
CMD ["python3", "app.py"]

