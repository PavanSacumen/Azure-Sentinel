import json
import logging
import base64
import hashlib
import hmac
from datetime import datetime
import requests
from config import Config


class SentinelLogger:
    """Handles sending logs to Microsoft Sentinel Log Analytics workspace."""

    def __init__(self):
        self.workspace_id = Config.get_env_variable("WORKSPACE_ID")
        self.shared_key = Config.get_env_variable("SHARED_KEY")
        self.log_type = Config.get_env_variable("LOG_TYPE", "CustomLogType")
        self.retry_times = int(Config.get_env_variable("RETRY_TIMES", 3))
        self.retry_interval = int(Config.get_env_variable("RETRY_INTERVAL", 10))

    def build_signature(self, date, content_length, method, content_type, resource):
        x_headers = f"x-ms-date:{date}"
        string_to_hash = (
            f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
        )
        bytes_to_hash = string_to_hash.encode("utf-8")
        decoded_key = base64.b64decode(self.shared_key)
        encoded_hash = hmac.new(
            decoded_key, bytes_to_hash, digestmod=hashlib.sha256
        ).digest()
        return base64.b64encode(encoded_hash).decode()

    def send_logs(self, log_data):
        log_data_json = json.dumps(log_data)
        resource = f"/api/logs"
        content_type = "application/json"
        rfc1123_date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        content_length = len(log_data_json)
        signature = self.build_signature(
            rfc1123_date, content_length, "POST", content_type, resource
        )
        uri = f"https://{self.workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
        headers = {
            "Content-Type": content_type,
            "Authorization": f"SharedKey {self.workspace_id}:{signature}",
            "Log-Type": self.log_type,
            "x-ms-date": rfc1123_date,
        }

        logging.info("Sending log data to Sentinel.")
        response = requests.post(uri, headers=headers, data=log_data_json)
        response.raise_for_status()
        logging.info("Log successfully sent to Sentinel.")
