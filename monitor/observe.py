"""Monitor process to handle notifications."""

import asyncio
import logging
from datetime import datetime, timedelta
from os import environ
from time import sleep

import elk_operations as elk
import handle_email as em
from apscheduler.schedulers.asyncio import AsyncIOScheduler

SYNC_INTERVAL = 60  # in minutes
COUNTRY_FILTER = environ.get("MONITOR_COUNTRY_FILTER")


def main() -> None:
    """Execute the main logic loop."""
    logging.info("Searching for new domains for notifications...")
    time_now = datetime.now()
    time_window_hour_ago = time_now - timedelta(minutes=SYNC_INTERVAL)

    # 1. Get all active domains now
    online_domains = elk.get_active_domains(
        SYNC_INTERVAL, country_filter=COUNTRY_FILTER
    )
    logging.info(
        f"Discovered {len(online_domains)} active phishing domains hosted in '{COUNTRY_FILTER}'"
    )

    # 2. Per domain, retrieve kit installation date
    notifications = 0
    for domain in online_domains:
        domain_kit_installation_date = elk.retrieve_kit_installed_date(domain)

        # When the kit installation timestamp if less than an hour ago, mark as new
        if domain_kit_installation_date > time_window_hour_ago:
            # Send notification
            logging.info(f"Send a notification email for domain: {domain}")
            em.send_notification_email(domain)
            notifications += 1
            sleep(2)

    logging.info(f"Monitoring done, {notifications} notifications sent.")


if __name__ == "__main__":
    # Initialize logging facilities
    logging_format = logging.Formatter(
        fmt="%(module)-20s:%(lineno)-3s [%(asctime)s] %(levelname)-8s%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Attach the right handlers and format to the logger
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging_format)
    logging.getLogger().handlers.clear()
    logging.getLogger().addHandler(stream_handler)
    logging.getLogger().setLevel(logging.INFO)
    logging.getLogger("elasticsearch").setLevel(logging.ERROR)
    logging.getLogger("elastic_transport").setLevel(logging.ERROR)

    # Define a asynchronous scheduler
    scheduler = AsyncIOScheduler(timezone="Europe/Amsterdam")

    # Add main as a job for a fixed interval, but also start first run right away
    scheduler.add_job(
        main,
        "interval",
        seconds=SYNC_INTERVAL * 60,
        next_run_time=datetime.now(),
        max_instances=1,
    )
    scheduler.start()
    try:
        asyncio.get_event_loop().run_forever()
    except (KeyboardInterrupt, SystemExit):
        logging.info("BigPhish monitor has stopped")
