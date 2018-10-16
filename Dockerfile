FROM python:3.6

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ /usr/src/app/

ENTRYPOINT ["python", "-m", "myca"]
CMD ["runserver", "--no-reload"]
