FROM node:20-bookworm-slim AS ui-builder

WORKDIR /app

COPY web-ui/package.json web-ui/package-lock.json ./web-ui/
WORKDIR /app/web-ui
RUN npm ci

COPY web-ui .
RUN npm run build

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY . .
COPY --from=ui-builder /app/src/server_doctor/web/static/spa ./src/server_doctor/web/static/spa

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

EXPOSE 8765

CMD ["uvicorn", "server_doctor.web.app:app", "--host", "0.0.0.0", "--port", "8765"]
