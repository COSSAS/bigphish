"""Certificate Transparency connector.

Inspired by https://github.com/CaliDog/certstream-python/blob/master/certstream/core.py
"""

import json
import logging
from time import sleep

import websocket


class Context(dict):
    """dot.notation access to dictionary attributes."""


class CertStreamClient(websocket.WebSocketApp):
    """Certstreamclient that wraps the WebSocket application.

    Args:
        websocket (WebSocketApp): WebSocketApp
    """

    _context = Context()

    def __init__(
        self, message_callback, url, skip_heartbeats=True, on_open=None, on_error=None
    ):
        """Certstreamclient initialization.

        Args:
            message_callback (Callable): function to handle the callback
            url (str): server URL
            skip_heartbeats (bool, optional): whether or not to ignore heartbeat messages. Defaults to True.
            on_open (Callable, optional): function to handle the start of messages flowing in. Defaults to None.
            on_error (Callable, optional): function to handle errors in the connection. Defaults to None.
        """
        self.message_callback = message_callback
        self.skip_heartbeats = skip_heartbeats
        self.on_open_handler = on_open
        self.on_error_handler = on_error
        super(CertStreamClient, self).__init__(
            url=url,
            on_open=self._on_open,
            on_message=self._on_message,
            on_error=self._on_error,
        )

    def _on_open(self, _):
        logging.info("Analyzing CertStream certificates.")
        if self.on_open_handler:
            self.on_open_handler()

    def _on_message(self, _, message):
        frame = json.loads(message)

        if frame.get("message_type", None) == "heartbeat" and self.skip_heartbeats:
            return

        self.message_callback(frame, self._context)

    def _on_error(self, _, error):
        if isinstance(error, KeyboardInterrupt):
            raise
        if self.on_error_handler:
            self.on_error_handler(error)
        logging.debug(error)
        logging.error("Connection to CertStream lost, reconnecting.")


def listen_for_events(
    message_callback, url, skip_heartbeats=True, on_open=None, on_error=None, **kwargs
):
    """Listen for new certificates in the Transparency Logs.

    Args:
        message_callback (def): function to use as a callback
        url (str): server URL
        skip_heartbeats (bool, optional): skip heartbeat messages or not. Defaults to True.
        on_open (def, optional): function to handle the open connection. Defaults to None.
        on_error (def, optional): function to handle the errors in the connection. Defaults to None.
    """
    try:
        while True:
            certstream_connection = CertStreamClient(
                message_callback,
                url,
                skip_heartbeats=skip_heartbeats,
                on_open=on_open,
                on_error=on_error,
            )
            certstream_connection.run_forever(
                ping_interval=15, ping_timeout=10, **kwargs
            )
            sleep(3)
    except KeyboardInterrupt:
        logging.info("Connection to CertStream terminated.")
