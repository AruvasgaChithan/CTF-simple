FROM python:3.11

WORKDIR /app

COPY requirements.txt /app/
RUN pip install -r requirements.txt

COPY src/ /app/src/
COPY templates/ /app/templates
COPY flags /app/flags
  # <-- ensure flags are included

EXPOSE 80
CMD ["python", "src/app.py"]
