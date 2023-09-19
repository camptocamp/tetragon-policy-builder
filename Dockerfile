FROM python:3-bookworm

WORKDIR /usr/src/
COPY . .

RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "-m", "builder"]
