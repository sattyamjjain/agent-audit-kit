FROM python:3.12-slim
WORKDIR /app
COPY app/ /app/
COPY cook.pth /usr/local/lib/python3.12/site-packages/
CMD ["python", "-m", "aak_placeholder_server"]
