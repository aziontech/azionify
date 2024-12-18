import logging
from typing import Dict, Any, Optional
from utils import clean_and_parse_json, sanitize_name


def get_main_setting_name(akamai_config: dict) -> str:
    """
    Deduces the main setting name from the Akamai configuration.
    """
    try:
        resources = akamai_config.get("resource", [])
        if not resources:
            logging.warning("No resources found in Akamai configuration.")
            return "default_main_setting"

        for resource in resources:
            if "akamai_property" in resource:
                akamai_property = resource["akamai_property"]
                for instance_name, instance_data in akamai_property.items():
                    property_name = instance_data.get("name", "default_main_setting")
                    logging.info(f"Found Akamai property: {property_name}")
                    return sanitize_name(property_name)

        logging.warning("No Akamai property found in resources.")
        return "default_main_setting"
    except KeyError as e:
        logging.error(f"KeyError while deducing main setting name: {e}")
        return "default_main_setting"
    except TypeError as e:
        logging.error(f"TypeError while processing Akamai configuration: {e}")
        return "default_main_setting"
    except ValueError as e:
        logging.error(f"Unexpected error while deducing main setting name: {e}")
        return "default_main_setting"

def extract_edge_hostname(akamai_config: dict) -> Optional[str]:
    """
    Extracts the edge hostname from Akamai configuration.

    Parameters:
        akamai_config (dict): Parsed Akamai Terraform configuration.

    Returns:
        str: Extracted edge hostname or None if not found.
    """
    try: 
        resource = akamai_config.get("resource", [])
        for item in resource:
            akamai_property = item.get("akamai_property", {})
            for property_name, property_data in akamai_property.items():
                hostnames = property_data.get("hostnames", [])
                for hostname_entry in hostnames:
                    if hostname_entry.get("cname_type") == "EDGE_HOSTNAME":
                        edge_hostname = hostname_entry.get("cname_to")
                        logging.info(f"Extracted edge_hostname: {edge_hostname} from hostnames")
                        return edge_hostname
                    
                hostname_data = property_data.get("akamai_edge_hostname", [])
                if isinstance(hostname_data, dict):
                    for instance_name, instance_data in hostname_data.items():
                        edge_hostname = instance_data.get("edge_hostname")
                        if edge_hostname:
                            logging.info(f"Extracted edge_hostname: {edge_hostname} from akamai_edge_hostname")
                            return edge_hostname

    except ValueError as e:
        print(f"Error in extract_edge_hostname: {e}")

    logging.warning("Edge hostname not found in Akamai configuration.")
    return None

def find_origin_hostname(akamai_config):
    """
    Extract the origin hostname from the Akamai property configuration.
    Handles cases where 'rules' is a JSON-encoded string and ensures robust handling of non-standard inputs.

    :param akamai_config: Dict representing the Akamai property configuration
    :return: The origin hostname if found, otherwise None
    """
    try:
        resource = akamai_config.get("resource", [])
        for item in resource:
            akamai_property = item.get("akamai_property", {})
            for property_name, property_data in akamai_property.items():
                rules = property_data.get("rules")

                if isinstance(rules, str):                    
                    rules = clean_and_parse_json(rules)
                    if rules is None:
                        logging.error("Invalid JSON after cleaning. Skipping.")
                        continue

                if not isinstance(rules, dict):
                    logging.error("Rules is not a dictionary. Skipping.")
                    continue

                # Process behaviors
                behaviors = rules.get("rules", {}).get("behaviors", [])
                for behavior in behaviors:
                    if behavior.get("name") == "origin":
                        options = behavior.get("options", {})
                        hostname = options.get("hostname")
                        if hostname:
                            logging.info(f"Found origin hostname: {hostname}")
                            return hostname

                # Process children
                children = rules.get("rules", {}).get("children", [])
                for child in children:
                    behaviors = child.get("behaviors", [])
                    for behavior in behaviors:
                        if behavior.get("name") == "origin":
                            options = behavior.get("options", {})
                            hostname = options.get("hostname")
                            if hostname:
                                logging.info(f"Found origin hostname in child: {hostname}")
                                return hostname

    except ValueError as e:
        logging.error(f"Error in find_origin_hostname: {e}")
    
    logging.debug("WARNING: Origin hostname not found. Returning None.")
    return None

def map_variable(value: str, context: str = "subject") -> str:
    """
    Dynamically maps Akamai variables to Azion-supported variables.

    Parameters:
        value (str): The Akamai variable to map.
        context (str): The context in which the variable is used (e.g., "subject", "captured_array", etc.).

    Returns:
        str: The mapped Azion variable.
    """
    # Context-aware mappings
    akamai_to_azion_map = {
        "subject": {
            "{{builtin.AK_PATH}}": "$${uri}",
            "{{request.uri}}": "$${request_uri}",
            "{{request.query_string}}": "$${args}",
            "{{request.header}}": "$${http_header}",
            "{{remote.addr}}": "$${remote_addr}",
            "{{host}}": "$${host}",
            # Add more mappings as needed...
        },
        "captured_array": {
            "PMUSER_REDIR": "$${variable}",
            "PMUSER_REDIR2": "$${variable}",
            "{{builtin.AK_PATH}}": "$${uri}",
            # Add more mappings as needed...
        },
        # Add more contexts and their mappings as necessary
    }

    # Get the appropriate mapping for the context
    context_map = akamai_to_azion_map.get(context, {})

    # Map the variable or return the original value as a fallback
    return context_map.get(value, value)

def map_origin_type(akamai_origin_type: str) -> str:
    """
    Map Akamai originType to Azion origin_type.

    Parameters:
        akamai_origin_type (str): The originType from Akamai configuration.

    Returns:
        str: The corresponding Azion origin_type.
    """
    origin_type_mapping = {
        "CUSTOMER": "single_origin",
        "NET_STORAGE": "object_storage",
        "MEDIA_SERVICE_LIVE": "live_ingest",
        "EDGE_LOAD_BALANCING_ORIGIN_GROUP": "load_balancer",
        "SAAS_DYNAMIC_ORIGIN": "single_origin",  # Adjust if a better mapping is found
    }

    return origin_type_mapping.get(akamai_origin_type, "single_origin")  # Default to single_origin

def map_forward_host_header(options: Dict[str, Any], default_host: str = "$${host}") -> str:
    """
    Map forwardHostHeader values from Akamai to Azion.

    Parameters:
        options (dict): Options containing forwardHostHeader configuration.
        default_host (str): Default host header value when no match is found.

    Returns:
        str: Mapped host header value.
    """
    forward_host_header = options.get("forwardHostHeader", "ORIGIN_HOSTNAME")
    custom_host_header = options.get("customForwardHostHeader")

    if forward_host_header == "REQUEST_HOST_HEADER":
        return "${host}"
    elif forward_host_header == "ORIGIN_HOSTNAME":
        return options.get("hostname", default_host)
    elif forward_host_header == "CUSTOM" and custom_host_header:
        return custom_host_header
    else:
        return options.get("hostname", default_host)

def map_origin_protocol_policy(options: Dict[str, Any]) -> str:
    """
    Maps Akamai's HTTP/HTTPS origin port settings to Azion's origin_protocol_policy.

    Parameters:
        options (Dict[str, Any]): Akamai origin options.

    Returns:
        str: Mapped value for Azion's origin_protocol_policy.
    """
    # Check for httpsPort and httpPort
    https_port = options.get("httpsPort")
    http_port = options.get("httpPort")

    # If both ports are explicitly set, return 'preserve'
    if https_port and http_port:
        return "preserve"
    elif https_port:  # If only httpsPort is set
        return "https"
    elif http_port:  # If only httpPort is set
        return "http"
    else:  # Default to 'preserve' if neither is explicitly set
        return "preserve"
