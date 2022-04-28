RUN apt-get update \
    && apt-get -y install libpq-dev gcc \
    && pip install psycopg2