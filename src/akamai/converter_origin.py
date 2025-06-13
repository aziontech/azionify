import logging
from typing import Dict, Any, Optional
from azion_resources import AzionResource
from utils import compact_and_sanitize, resources_filter_by_type
from akamai.utils import map_origin_protocol_policy, map_origin_type, map_forward_host_header


def create_origin(
        context: Dict[str, Any],
        azion_resources: AzionResource,
        origin_attributes: Dict[str, Any],
        main_setting_name: str,
        edge_hostname: Optional[str],
        name: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
    """
    Creates the origin resource for Azion, dynamically mapping Akamai addresses.

    Parameters:
        azion_resources (AzionResource): The Azion resource container.
        origin_attributes (Dict[str, Any]): Attributes from Akamai configuration.
        main_setting_name (str): Name of the main Azion edge application resource.
        edge_hostname (Optional[str]): The edge hostname extracted from Akamai configuration.
        name (Optional[str]): Name of the origin resource.

    Returns:
        Optional[Dict[str, Any]]: Azion-compatible origin resource.
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
        host_header = map_forward_host_header(options)
        global_settings = resources_filter_by_type(azion_resources.get_azion_resources(), "global_settings")
        environment = global_settings[0].get("attributes", {}).get("environment", "production")

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
        index = context.get("rule_index", 0)
        name = name +"_"+ host_header + "_" + str(index) if name else f'{origin_attributes.get("name", "Default Origin")}_{index}'
        name = compact_and_sanitize(name)
        if environment != "production":
            name = f"{name}_{environment}"
        origin_resource = {
            "type": "azion_edge_application_origin",
            "name": name,
            "attributes": {
                "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.edge_application.application_id",
                "origin": {
                    "name": name,
                    "origin_type": origin_type,
                    "addresses": addresses,
                    "origin_protocol_policy": origin_protocol_policy,
                    "host_header": host_header,
                    "origin_path": origin_path,
                    "connection_timeout": connection_timeout,
                    "timeout_between_bytes": timeout_between_bytes,
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
