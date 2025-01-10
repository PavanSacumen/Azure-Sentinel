import json
import logging
import os
import time
import requests
import azure.functions as func
from sentinel_handler import SentinelLogger
from config import Config


def retry(retry_times, retry_interval):
    """A decorator to retry a function/method upon failure."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            for attempt in range(1, retry_times + 1):
                try:
                    logging.info(f"Attempt {attempt} for {func.__name__}.")
                    return func(*args, **kwargs)
                except Exception as e:
                    logging.error(f"Attempt {attempt} failed: {e}")
                    if attempt < retry_times:
                        logging.info(f"Retrying in {retry_interval} seconds...")
                        time.sleep(retry_interval)
                    else:
                        logging.error(f"All {retry_times} attempts failed.")
                        raise

        return wrapper
    
    return decorator


class DataProcessor:
    """Handles data processing tasks such as excluding fields."""

    @staticmethod
    def exclude_fields(data, excluded_fields):
        if isinstance(data, dict):
            sanitized_data = {}
            for key, value in data.items():
                if key not in excluded_fields:
                    # Check for nested exclusions using dot notation
                    nested_exclusions = [
                        field[len(key) + 1 :]
                        for field in excluded_fields
                        if field.startswith(f"{key}.")
                    ]
                    sanitized_data[key] = DataProcessor.exclude_fields(
                        value, nested_exclusions
                    )
                else:
                    logging.info(f"Excluded field: {key}")
            return sanitized_data
        elif isinstance(data, list):
            return [
                DataProcessor.exclude_fields(item, excluded_fields) for item in data
            ]
        return data


class ADRHandler:
    """Handles processing of ADR events."""

    def __init__(self, req_body):
        self.req_body = req_body
        self.organization_uuid = Config.get_env_variable("ORGANIZATIONAL_UID")
        self.base_url = Config.get_env_variable("BASE_URL", "")
        self.endpoint_template = Config.get_env_variable("ENDPOINT_TEMPLATE", "")
        self.excluded_fields = [
            field.strip()
            for field in Config.get_env_variable("EXCLUDED_FIELDS", "").split(",")
            if field.strip()
        ]
        self.retry_times = int(Config.get_env_variable("RETRY_TIMES", 3))
        self.retry_interval = int(Config.get_env_variable("RETRY_INTERVAL", 10))

    @retry(
        retry_times=int(Config.get_env_variable("RETRY_TIMES", 3)),
        retry_interval=int(Config.get_env_variable("RETRY_INTERVAL", 10)),
    )
    def enrich_data(self, attack_event_uuid, application_uuid):
        endpoint = self.endpoint_template.format(
            org_uuid=self.organization_uuid,
            app_uuid=application_uuid,
            event_uuid=attack_event_uuid,
        )
        full_url = f"{self.base_url}{endpoint}"
        timeout = int(Config.get_env_variable("TIMEOUT"))
        logging.info(f"Making a GET request to {full_url}")
        response = requests.get(full_url, timeout=timeout)
        response.raise_for_status()
        return response.json()

    def process_request(self):
        attack_event_uuid, application_uuid = self.validate_request()
        enrichment_enabled = os.getenv("ENRICHMENT_DATA_SUBSCRIPTION") == "TRUE"

        if enrichment_enabled:
            try:
                response_data = self.enrich_data(attack_event_uuid, application_uuid)
            except Exception as e:
                # Fallback to using webhook data
                logging.error(f"Enrichment API call failed: {e}")
                response_data = self.req_body
        else:
            response_data = self.req_body

        return DataProcessor.exclude_fields(response_data, self.excluded_fields)

    def validate_request(self):
        attack_event_uuid = self.req_body.get("eventUuid")
        application_uuid = self.req_body.get("application", {}).get("id")

        if not attack_event_uuid or not application_uuid:
            raise ValueError("Missing required fields in JSON payload")

        return attack_event_uuid, application_uuid


# Azure Function Definition
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


@app.route(route="contrast_ADR_trigger")
def contrast_ADR_trigger(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Python HTTP trigger function processed a request.")

    try:
        # Parse request body
        try:
            req_body = req.get_json()
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON payload: {e}")
            return func.HttpResponse("Invalid JSON payload", status_code=400)

        adr_handler = ADRHandler(req_body)

        # Process the request
        sanitized_response = adr_handler.process_request()

        # send data to sentinel
        sentinel_logger = SentinelLogger()
        try:
            sentinel_logger.send_logs(sanitized_response)
        except Exception as e:
            logging.error(f"Failed to send logs to Sentinel after retries: {e}")

        return func.HttpResponse(
            json.dumps(sanitized_response),
            status_code=200,
            mimetype="application/json",
        )
    except ValueError as ve:
        logging.error(f"Validation error: {ve}")
        return func.HttpResponse(str(ve), status_code=400)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return func.HttpResponse(
            "An error occurred while processing the request", status_code=500
        )
