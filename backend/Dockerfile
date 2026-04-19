FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Comando para rodar a aplicação chamando o script python para garantir que init_db() seja executado
CMD ["python", "app/main.py"]
