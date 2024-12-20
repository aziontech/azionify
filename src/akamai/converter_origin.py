import logging
from typing import Dict, Any, Optional
from azion_resources import AzionResource
from utils import sanitize_name
from akamai.utils import map_origin_protocol_policy, map_origin_type, map_forward_host_header

def create_origin(azion_resources: AzionResource, origin_attributes: Dict[str, Any], main_setting_name: str, edge_hostname: Optional[str], name: Optional[str] = None) -> Optional[Dict[str, Any]]:
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

        logging.debug(f"Origin Attributes content: {origin_attributes}")

        options = origin_attributes.get("options", {})

        # Extract origin-specific details
        hostname = options.get("hostname") or edge_hostname or "placeholder.example.com"
        origin_type = map_origin_type(options.get("originType", "CUSTOMER"))
        origin_protocol_policy = map_origin_protocol_policy(options)
        origin_path = options.get("baseDirectory", "")
        connection_timeout = options.get("connection_timeout", 60)
        timeout_between_bytes = options.get("timeout_between_bytes", 120)
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
                "weight": options.get("weight", None),
            }
        ]

        # HMAC Authentication
        hmac_authentication = options.get("hmac_authentication", False)
        hmac_region_name = options.get("hmac_region_name", "")
        hmac_access_key = options.get("hmac_access_key", "")
        hmac_secret_key = options.get("hmac_secret_key", "")

        # Validate extracted hostname
        if not hostname or hostname == "placeholder.example.com":
            logging.warning(f"Hostname not properly set. Using placeholder: {hostname}")

        # Construct the origin resource
        origin_resource = {
            "type": "azion_edge_application_origin",
            "name": sanitize_name(name if name else origin_attributes.get("name", "Default Origin")),
            "attributes": {
                "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.edge_application.application_id",
                "origin": {
                    "name": sanitize_name(name if name else origin_attributes.get("name", "Default Origin")),
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