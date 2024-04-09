"""Email utilities."""

import logging
import smtplib
import ssl
from email.message import EmailMessage
from os import environ

PORT = int(environ.get("NOTIFICATION_EMAIL_PORT", 0))
SMTP_SERVER = str(environ.get("NOTIFICATION_EMAIL_SERVER"))

SENDER_EMAIL = str(environ.get("NOTIFICATION_EMAIL_SENDER"))
RECEIVER_EMAIL = str(environ.get("NOTIFICATION_EMAIL_RECEIVER"))
PASSWORD = str(environ.get("NOTIFICATION_EMAIL_PASSWORD"))
BIGPHISH_SERVER_NAME = environ.get("SERVER_NAME")

SERVER_NAME = str(environ.get("SERVER_NAME"))


def send_notification_email(domain: str) -> None:
    """Send a notification email to a specific email adress.

    Args:
        domain (str): domain to notify about
    """
    # Create email body
    body = f"""\

    A new phishing domain has been discovered! 
    
    Domain: {domain}
    More information: https://{SERVER_NAME}/domain/?domain={domain}

    -- BigPhish

    """
    subject = f"[BigPhish] New phishing domain: {domain}"

    # Set headers
    notification_email = EmailMessage()
    notification_email["From"] = SENDER_EMAIL
    notification_email["To"] = RECEIVER_EMAIL
    notification_email["Subject"] = subject
    notification_email.set_content(body)

    # Send email using SMTP
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_SERVER, PORT, context=context) as server:
        server.login(SENDER_EMAIL, PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, notification_email.as_string())
        logging.info("Notification sent succesfully")
