import logging
from typing import Dict, Any, Optional
from azion_resources import AzionResource
from utils import clean_and_parse_json


def validate_and_apply_defaults(attributes: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates and applies default values to the given attributes based on provided defaults.

    Parameters:
        attributes (dict): The input attributes to validate.
        defaults (dict): Default values for the attributes.

    Returns:
        dict: A dictionary containing the validated and normalized attributes.
    """
    validated = {}
    
    for key, default_value in defaults.items():
        # Extract the current value from attributes or use the default
        value = attributes.get(key, default_value)

        # Perform specific validations based on the key
        if key == "delivery_protocol" and value not in {"http", "https", "http,https"}:
            logging.warning(f"Invalid delivery_protocol '{value}', defaulting to '{default_value}'.")
            value = default_value

        elif key == "minimum_tls_version" and value not in {"", "tls_1_0", "tls_1_1", "tls_1_2", "tls_1_3"}:
            logging.warning(f"Invalid minimum_tls_version '{value}', defaulting to '{default_value}'.")
            value = default_value

        elif key == "supported_ciphers" and value not in {"all", "TLSv1.2_2018", "TLSv1.2_2019", "TLSv1.2_2021", "TLSv1.3_2022"}:
            logging.warning(f"Invalid supported_ciphers '{value}', defaulting to '{default_value}'.")
            value = default_value

        elif key == "http_port" or key == "https_port":
            if not isinstance(value, list) or not all(isinstance(port, int) for port in value):
                logging.warning(f"Invalid {key} '{value}', defaulting to '{default_value}'.")
                value = default_value

        elif isinstance(default_value, bool) and not isinstance(value, bool):
            logging.warning(f"Invalid boolean value for {key} '{value}', defaulting to '{default_value}'.")
            value = default_value

        # Apply the validated or default value to the result
        validated[key] = value

    return validated

def create_main_setting(azion_resources: AzionResource, attributes: Dict[str, Any], main_setting_name: str) -> Optional[Dict[str, Any]]:
    """
    Creates the main application setting resource for Azion.

    Parameters:
        attributes (dict): Attributes from Akamai configuration.
        main_setting_name (str): Name of the main Azion edge application resource.

    Returns:
        dict: Azion-compatible main_setting resource.
    """
    defaults = {
        "name": "Default Edge Application",
        "delivery_protocol": "http,https",
        "http_port": [80],
        "https_port": [443],
        "supported_ciphers": "TLSv1.2_2021",
        "minimum_tls_version": "tls_1_2",
        "debug_rules": False,
        "caching": True,
        "edge_firewall": True,
        "edge_functions": True,
        "image_optimization": False,
        "http3": False,
        "application_acceleration": False,
        "l2_caching": False,
        "load_balancer": False,
        "raw_logs": True,
        "device_detection": False,
        "web_application_firewall": False,
    }

    validated_attributes = validate_and_apply_defaults(attributes, defaults)

    # Search for HTTP/2 settings in behaviors
    try:
        rules = attributes.get("rules", {})
        behaviors = []
        if isinstance(rules, str):
            logging.debug("Rules attribute is a string reference. Converting to JSON content.")
            rules = clean_and_parse_json(rules)
            if rules:
                rules = rules.get("rules", {})
            else:
                logging.error("Failed to parse rules or empty rules content.")
                rules = {}
        if isinstance(rules, dict):
            behaviors = rules.get("behaviors", [])
        else:
            logging.warning("Unexpected type for rules. Defaulting to empty behaviors.")
            logging.debug(f"Rules attribute content: {rules}")

        logging.debug(f"Behaviors attribute content: {behaviors}")

        if isinstance(behaviors, list):
            http2_behavior = next((b for b in behaviors if isinstance(b, dict) and b.get("name") == "http2"), None)
            if http2_behavior:
                options = http2_behavior.get("options", {})
                if options.get("enabled", True):
                    validated_attributes["http3"] = True
        else:
            logging.warning("Behaviors is not a list. Skipping HTTP/2 processing.")
    except AttributeError as e:
        logging.warning(f"Could not process HTTP/2 settings: {e}")

    return {
        "type": "azion_edge_application_main_setting",
        "name": main_setting_name,
        "attributes": {
            "edge_application": validated_attributes
        }
    }