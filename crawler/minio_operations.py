"""Functionalities to communicate with the MinIO object storage."""

import io
import logging
from os import environ
from typing import List

import requests
from minio import Minio  # type: ignore

MINIO_HOST = environ.get("MINIO_HOST", "")
MINIO_ACCESS_KEY = environ.get("MINIO_ROOT_USER", "")
MINIO_SECRET_KEY = environ.get("MINIO_ROOT_PASSWORD", "")


def create_minio_client() -> Minio:
    """
    Create a new MinIO client to connect with the object storage.

    :return:
    """
    return Minio(
        endpoint=MINIO_HOST,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False if not MINIO_HOST.startswith("https") else True,
    )


def check_and_create_buckets(buckets: List[str]) -> None:
    """
    Check if a list of buckets exists, if not, create them.

    :param buckets:
    :return:
    """
    try:
        # Create client for connection to MinIO
        client = create_minio_client()

        # Create a bucket if it does not exist yet
        for bucket in buckets:
            if not client.bucket_exists(bucket):
                client.make_bucket(bucket)

    except Exception as error:
        logging.error(f"MinIO error: {error}")


def store_object(data: bytes, file_name: str, bucket: str) -> None:
    """
    Store an object in MinIO object storage.

    :param data: bytes object
    :param file_name: str
    :param bucket: bucket name to store it in
    :return:
    """
    try:
        # Create client for connection to MinIO
        client = create_minio_client()

        # Get the raw bytes and the file size
        raw_data = io.BytesIO(data)
        raw_data_size = raw_data.getbuffer().nbytes

        # Upload the data to MinIO
        result = client.put_object(bucket, file_name, raw_data, raw_data_size)
        logging.debug(f"Stored file: {result.object_name} at {result.location}")

    except Exception as error:
        logging.error(f"MinIO error: {error}")


def test_minio() -> bool:
    """
    Check if a connection to MinIO can be established.

    :return:
    """
    try:
        res = requests.get(f"http://{MINIO_HOST}/minio/health/ready")
        if res.ok:
            return True
    except Exception as error:
        logging.error(
            f"MinIO connection to {MINIO_HOST} could not be established: {error}"
        )
    return False
