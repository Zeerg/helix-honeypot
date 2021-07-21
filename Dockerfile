FROM python:3.8-slim

RUN adduser python
WORKDIR /app
COPY . /app
RUN chown -R python:python /app \
    && pip install pipenv \
    && pipenv install --system --deploy --ignore-pipfile
USER python
EXPOSE 8000
CMD ["gunicorn" "-w" "1" "-b" "0.0.0.0:8000" "wsgi:helix_honeypot" "--access-logfile" "-"]