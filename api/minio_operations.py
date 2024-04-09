"""Functionalities to communicate with the MinIO object storage."""

import base64
import logging
from os import environ
from typing import Any, Dict

import requests

from minio import Minio  # type:ignore

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


def retrieve_screenshot(
    domain: str, screenshot_hash: str, bucket: str = "screenshots"
) -> str:
    """
    Retrieve a screenshot from MinIO object storage.

    :param domain:
    :param screenshot_hash:
    :param bucket:
    :return:
    """
    try:
        # Create client for connection to MinIO
        client = create_minio_client()

        # Get data of an object and convert to valid base64 image string
        response = client.get_object(bucket, f"{domain}/{screenshot_hash}.png")
        base64_screenshot = base64.b64encode(response.data).decode()

        # Close and release the connection
        response.close()
        response.release_conn()

        return f"data:image/png;base64,{base64_screenshot}"

    except Exception as error:
        logging.error(f"MinIO error: {error}")
        return ""


def retrieve_all_screenshots(
    domain: str, bucket: str = "screenshots"
) -> Dict[str, str]:
    """
    Retrieve all screenshots for a given domain.

    :param domain:
    :param bucket:
    :return: dict of screenshot hash-file pairs
    """
    entries = {}

    try:
        # Create client for connection to MinIO
        client = create_minio_client()

        # Get all the file names of screenshots in this folder
        objects_in_folder = client.list_objects(bucket, prefix=f"{domain}/")
        for screenshot_object in objects_in_folder:
            response = client.get_object(bucket, screenshot_object.object_name)
            base64_screenshot = base64.b64encode(response.data).decode()

            screenshot_hash = screenshot_object.object_name.replace(
                f"{domain}/", ""
            ).split(".")[-2]
            entries[screenshot_hash] = f"data:image/png;base64,{base64_screenshot}"

            # Close and release the connection
            response.close()
            response.release_conn()

    except Exception as error:
        logging.error(f"MinIO error: {error}")

    return entries


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
