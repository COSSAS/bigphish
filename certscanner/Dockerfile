FROM python:3.11-slim-bookworm

WORKDIR /certscanner

# Install requirements
COPY requirements.txt requirements.txt
RUN python3 -m pip install --upgrade pip && pip3 install -r requirements.txt

# Copy all necessary files and scripts
COPY *.py *.json /certscanner/

# Start the certificate scanner
CMD ["python3", "certscanner.py"]