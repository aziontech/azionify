import logging
from typing import Dict, Any, Optional
from azion_resources import AzionResource
from utils import clean_and_parse_json
from akamai.utils import map_origin_type, map_forward_host_header

def create_origin(azion_resources: AzionResource, attributes: Dict[str, Any], main_setting_name: str, edge_hostname: Optional[str]) -> Dict[str, Any]:
    """
    Creates the origin resource for Azion, dynamically mapping Akamai addresses.

    Parameters:
        attributes (dict): Attributes from Akamai configuration.
        main_setting_name (str): Name of the main Azion edge application resource.
        edge_hostname (Optional[str]): The edge hostname extracted from Akamai configuration.

    Returns:
        dict: Azion-compatible origin resource.
    """
    try:
        logging.info("Creating Azion origin resource.")

        # Extract and validate rules
        rules = attributes.get("rules", {})
        behaviors = []
        if isinstance(rules, str):
            logging.warning("Rules attribute is a string reference. Converting to JSON content.")
            rules = clean_and_parse_json(rules).get("rules", {})

        if isinstance(rules, dict):
            behaviors = rules.get("behaviors", [])
        else:
            logging.warning("Unexpected type for rules. Defaulting to empty behaviors.")
            logging.debug(f"Rules attribute content: {rules}")

        logging.debug(f"Behaviors attribute content: {behaviors}")

        # Extract origin behavior
        origin_behavior = next((b for b in behaviors if b.get("name") == "origin"), {})
        options = origin_behavior.get("options", {})

        # Extract origin-specific details
        hostname = options.get("hostname") or edge_hostname or "placeholder.example.com"
        origin_type = map_origin_type(options.get("originType", "CUSTOMER"))
        origin_protocol_policy = options.get("origin_protocol_policy", "preserve")
        origin_path = options.get("originPath", "/")
        connection_timeout = options.get("connection_timeout", 10)
        timeout_between_bytes = options.get("timeout_between_bytes", 5)
        is_origin_redirection_enabled = options.get("is_origin_redirection_enabled", False)
        host_header = map_forward_host_header(options)

        if not hostname or hostname == "placeholder.example.com":
            logging.warning(f"Hostname not properly set. Using placeholder: {hostname}")

        # Address details
        addresses = [
            {
                "address": hostname,
                "is_active": options.get("is_active", True),
                "server_role": options.get("server_role", "primary"),
                "weight": options.get("weight", 1),
            }
        ]

        # HMAC Authentication
        hmac_authentication = attributes.get("hmac_authentication", False)
        hmac_region_name = attributes.get("hmac_region_name", "")
        hmac_access_key = attributes.get("hmac_access_key", "")
        hmac_secret_key = attributes.get("hmac_secret_key", "")

        # Validate extracted hostname
        if not hostname or hostname == "placeholder.example.com":
            logging.warning(f"Hostname not properly set. Using placeholder: {hostname}")

        # Construct the origin resource
        origin_resource = {
            "type": "azion_edge_application_origin",
            "name": attributes.get("name", "Default Origin"),
            "attributes": {
                "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.edge_application.application_id",
                "origin": {
                    "name": attributes.get("name", "Default Origin"),
                    "origin_type": origin_type,
                    "addresses": addresses,
                    "origin_protocol_policy": origin_protocol_policy,
                    "host_header": host_header,
                    "origin_path": origin_path,
                    "connection_timeout": connection_timeout,
                    "timeout_between_bytes": timeout_between_bytes,
                    "is_origin_redirection_enabled": is_origin_redirection_enabled,
                    "hmac_authentication": hmac_authentication,
                    "hmac_region_name": hmac_region_name,
                    "hmac_access_key": hmac_access_key,
                    "hmac_secret_key": hmac_secret_key,
                },
                "depends_on": [f"azion_edge_application_main_setting.{main_setting_name}"],
            },
        }

        logging.info(f"Origin resource created with hostname: {hostname}")
        return origin_resource

    except Exception as e:
        logging.error(f"Error creating origin resource: {e}")
        raise