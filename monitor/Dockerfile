FROM python:3.11.4-buster

WORKDIR /monitor

# Install requirements
COPY requirements.txt requirements.txt
RUN python3 -m pip install --upgrade pip && pip3 install -r requirements.txt

# Copy all necessary files and scripts
COPY *.py  /monitor/

# Start the certificate scanner
CMD ["python3", "observe.py"]