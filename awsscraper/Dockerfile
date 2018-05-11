FROM python:3-slim

WORKDIR /opt/awsscraper

COPY Pipfile .
COPY Pipfile.lock .

RUN pip install pipenv

RUN useradd -u 2828 -ms /bin/bash awsscraper 
RUN chsh -s /usr/sbin/nologin root
USER awsscraper

RUN pipenv install --three

COPY dnsscraper.py .
COPY routes.py .
COPY teams.config .
COPY static static
COPY templates templates

EXPOSE 5000
ENTRYPOINT ["pipenv", "run", "python3", "routes.py"]

