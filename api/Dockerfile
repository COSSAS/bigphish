FROM python:3.11.9-slim-bookworm

WORKDIR /api

COPY ./requirements.txt /

RUN python3 -m pip install --upgrade pip && pip install -r /requirements.txt

COPY *.py .

# Create a seperate user that is not root
RUN useradd --user-group --system --no-log-init api-user
RUN chown api-user:api-user -R /api/
USER api-user

# Start the API with uvicorn
CMD ["uvicorn", "main:app", "--host=0.0.0.0", "--port=5000"]