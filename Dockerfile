FROM python:3-alpine

# Commands from python -onbuild dockerfile
RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r requirements.txt

ADD db.yaml /
ADD bin /bin
ENV HOME /root
RUN mkdir -p ~/.ssh/

ENTRYPOINT ["/bin/token-dispenser.py", "/db.yaml", "80"]
