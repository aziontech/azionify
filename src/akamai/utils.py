import logging
import re
from typing import Dict, Any, Optional, List
from utils import clean_and_parse_json, sanitize_name

OPERATOR_MAP = {
    "EQUALS": "is_equal",
    "EQUALS_ONE_OF": "is_equal",
    "DOES_NOT_EQUAL": "is_not_equal",
    "DOES_NOT_EQUAL_ONE_OF": "is_not_equal",
    "MATCHES": "matches",
    "MATCHES_ONE_OF": "matches",
    "DOES_NOT_MATCH": "does_not_match",
    "DOES_NOT_MATCH_ONE_OF": "does_not_match",
    "STARTS_WITH": "starts_with",
    "STARTS_WITH_ONE_OF": "starts_with",
    "DOES_NOT_START_WITH": "does_not_start_with",
    "EXISTS": "exists",
    "DOES_NOT_EXIST": "does_not_exist",
    "IS_ONE_OF": "is_equal",
    "IS_NOT_ONE_OF": "is_not_equal"
}

# Context-aware mappings (direct mapping based on Akamai builtin variable)
AKAMAI_TO_AZION_MAP = {
    "AK_PATH": "$${uri}",
    "AK_CLIENT_IP": "$${remote_addr}",
    "AK_ORIGINAL_URL": "$${request}",
    "AK_SCHEME": "$${scheme}",
    "AK_QUERY": "$${args}",
    "AK_METHOD": "$${request_method}",
    "AK_HOST": "$${host}",
    "AK_TLS_VERSION": "$${tls_version}",
    "AK_CLIENT_REAL_IP": "$${remote_addr}",
    "AK_CLIENT_RTT": "$${rtt}",
    "AK_CLIENT_USER_AGENT": "$${user_agent}",
    "AK_CLIENT_ACCEPT_LANGUAGE": "$${http_accept_language}",
    "AK_CLIENT_ACCEPT_ENCODING": "$${http_accept_encoding}",
    "AK_CLIENT_ACCEPT_CHARSET": "$${http_accept_charset}",
    "AK_CLIENT_COOKIE": "$${cookie_name}",
    "AK_CLIENT_REFERER": "$${http_referer}",
    "PMUSER_REDIR": "$${variable}",
    "PMUSER_REDIR2": "$${variable}",
    # Add more mappings as needed...
}

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
        logging.error(f"Error in extract_edge_hostname: {e}")

    logging.warning("Edge hostname not found in Akamai configuration.")
    return None

def find_origin_hostname(akamai_config: Dict[str, Any]) -> Optional[str]:
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

def map_variable(value: str) -> str:
    """
    Dynamically maps Akamai variables to Azion-supported variables.

    Parameters:
        value (str): The Akamai variable to map.

    Returns:
        str: The mapped Azion variable.
    """
    # Check if the variable has the 'builtin.' prefix and remove it if present
    if value.startswith("{{builtin."):
        value = value.replace("{{builtin.", "").replace("}}", "")
    if value.startswith("{{user."):
        value = value.replace("{{user.", "").replace("}}", "")

    # Get the appropriate mapping for the variable or return the original value as a fallback
    return AKAMAI_TO_AZION_MAP.get(value, value)

def replace_variables(input_string: str) -> str:
    """
    Replaces Akamai variables in the input string with their Azion equivalents.

    Parameters:
        input_string (str): The input string potentially containing Akamai variables.

    Returns:
        str: The string with Akamai variables replaced by Azion equivalents.
    """
    # Regular expression pattern to match Akamai variables, e.g., {{builtin.AK_PATH}}
    pattern = r"{{(builtin|user)\.[a-zA-Z0-9_\.]+}}"
    
    # Function to replace the matched variable with its mapped Azion value
    def replace_match(match):
        variable = match.group(0)
        return map_variable(variable)

    # Replace all occurrences of Akamai variables in the string using the regex pattern
    modified_string = re.sub(pattern, replace_match, input_string)

    # Return the modified string, or the original if no replacements were made
    return modified_string if modified_string != input_string else input_string

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
        return "$${host}"
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

def map_operator(akamai_operator: str) -> str:
    """
    Maps Akamai operators to Azion operators.
    
    Parameters:
        akamai_operator (str): Akamai operator
        
    Returns:
        str: Azion operator
    """
    return OPERATOR_MAP.get(akamai_operator, "matches")  # default to matches if unknown

def is_positive_operator(operator: str) -> bool:
    """
    Determines if an operator represents a positive or negative operation.
    
    Args:
        operator (str): The operator to check
        
    Returns:
        bool: True if the operator is positive (EQUALS, MATCHES, etc),
              False if negative (DOES_NOT_EQUAL, DOES_NOT_MATCH, etc)
    """
    negative_operators = {
        "DOES_NOT_EQUAL", "DOES_NOT_EQUAL_ONE_OF",
        "DOES_NOT_MATCH", "DOES_NOT_MATCH_ONE_OF",
        "DOES_NOT_START_WITH", "DOES_NOT_EXIST",
        "IS_NOT_ONE_OF"
    }
    return operator not in negative_operators

def behavior_key(behavior: dict) -> str:
    """
    Creates a unique string key for a behavior based on its name and target parameters.

    Parameters:
        behavior (dict): The behavior dictionary containing 'name' and optional 'target' keys.

    Returns:
        str: A unique string key combining the behavior name and its target parameters.
    """
    target_items = sorted(behavior.get("target", {}).items())
    target_str = "_".join(f"{k}:{v}" for k, v in target_items) if target_items else ""
    return f"{behavior['name']}_{target_str}" if target_str else behavior["name"]

def get_input_hostname(values: List[str]) -> str:
    # Convert hostname patterns to regex patterns
    patterns = []
    for value in values:
        if value.startswith('*.'):
            # Convert *.domain.com to regex pattern that matches any subdomain
            # First replace dots with escaped dots, then replace *. with the pattern
            value_with_escaped_dots = value[2:].replace('.', r'\\.')  # Remove *. and escape remaining dots
            pattern = f'[^.]+\\\\.{value_with_escaped_dots}'  # Triple backslash for the dot after [^.]+
        else:
            pattern = value.replace('.', r'\\.')
        patterns.append(pattern)
    return r"^(%s)$" % "|".join(patterns)

def get_redirect_target(options: Dict[str, Any]) -> str:
    """
    Generate redirect target based on Akamai redirect behavior options.
    Maps Akamai redirect variables to Azion compatible format.
    
    Args:
        options: Dictionary containing Akamai redirect configuration
        
    Supported options:
    - destinationProtocol: SAME_AS_REQUEST, HTTP, HTTPS
    - destinationHostname: SAME_AS_REQUEST, SUBDOMAIN, SIBLING, OTHER
    - destinationPath: SAME_AS_REQUEST, PREFIX_REQUEST, OTHER
    - queryString: APPEND or IGNORE
    
    Returns:
        str: URL template string wrapped in double quotes
    """
    # Handle protocol
    protocol = options.get('destinationProtocol', 'SAME_AS_REQUEST')
    scheme = {
        'SAME_AS_REQUEST': '$${scheme}',
        'HTTP': 'http',
        'HTTPS': 'https'
    }.get(protocol, '$${scheme}')
    
    # Handle hostname
    hostname_type = options.get('destinationHostname', 'SAME_AS_REQUEST')
    if hostname_type == 'SAME_AS_REQUEST':
        hostname = '$${host}'
    elif hostname_type == 'SUBDOMAIN':
        subdomain = options.get('destinationHostnameSubdomain', '')
        hostname = f"{subdomain}.$${{'host'}}"
    elif hostname_type == 'SIBLING':
        sibling = options.get('destinationHostnameSibling', '')
        hostname = '$${host}'.replace('www.', f"{sibling}.")
    elif hostname_type == 'OTHER':
        hostname = replace_variables(options.get('destinationHostnameOther', '$${host}'))
    else:
        hostname = '$${host}'
    
    # Handle path and query string
    path_type = options.get('destinationPath', 'SAME_AS_REQUEST')
    if path_type == 'SAME_AS_REQUEST':
        path = '$${uri}'
        query_string = '$${args}' if options.get('queryString') == 'APPEND' else ''
    elif path_type == 'PREFIX_REQUEST':
        prefix = options.get('destinationPathPrefix', '')
        suffix_status = options.get('destinationPathSuffixStatus', 'NO_SUFFIX')
        suffix = options.get('destinationPathSuffix', '') if suffix_status == 'SUFFIX' else ''
        path = f"{prefix}/$${{'uri'}}{suffix}"
        query_string = '$${args}' if options.get('queryString') == 'APPEND' else ''
    elif path_type == 'OTHER':
        other_path = replace_variables(options.get('destinationPathOther', ''))
        if not other_path:
            path = '$${uri}'
            query_string = '$${args}' if options.get('queryString') == 'APPEND' else ''
        else:
            path = other_path
            query_string = ''
    else:
        path = '$${uri}'
        query_string = '$${args}' if options.get('queryString') == 'APPEND' else ''
    
    # Build final URL
    url = f"{scheme}://{hostname}"
    if path:
        # Remove duplicate slashes and ensure path starts with /
        while '//' in path:
            path = path.replace('//', '/')
        if not path.startswith('/'):
            path = '/' + path
        url = f"{url}{path}"
    if query_string and '?' not in url:
        url = f"{url}?{query_string}"
    
    return f'"{url}"'
