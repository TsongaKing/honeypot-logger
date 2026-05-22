FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

RUN mkdir -p logs reports

EXPOSE 21 22 80 3306 8080

CMD ["python", "main.py", "--ports", "21,22,80,3306,8080"]
