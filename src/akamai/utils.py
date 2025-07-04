import logging
import re
import copy
from typing import Dict, Any, Optional, List, Union
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
    "AK_CLIENT_REFERER": "$${http_referer}"
    # Add more mappings as needed...
}

HTTP_HEADERS = {
    "CACHE_CONTROL": "Cache-Control",
    "CONTENT_DISPOSITION": "Content-Disposition",
    "CONTENT_TYPE": "Content-Type",
    "EDGE_CONTROL": "Edge-Control",
    "P3P": "P3P",
    "PRAGMA": "Pragma",
    "ACCESS_CONTROL_ALLOW_ORIGIN": "Access-Control-Allow-Origin",
    "ACCESS_CONTROL_ALLOW_METHODS": "Access-Control-Allow-Methods",
    "ACCESS_CONTROL_ALLOW_HEADERS": "Access-Control-Allow-Headers",
    "ACCESS_CONTROL_EXPOSE_HEADERS": "Access-Control-Expose-Headers",
    "ACCESS_CONTROL_ALLOW_CREDENTIALS": "Access-Control-Allow-Credentials",
    "ACCESS_CONTROL_MAX_AGE": "Access-Control-Max-Age"
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
                    if hostname_entry.get("cname_type","EDGE_HOSTNAME") in ["EDGE_HOSTNAME", "CUSTOM"]:
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
    if value.startswith('PMUSER_'):
        value = value.removeprefix('PMUSER_')[:10]

    # Get the appropriate mapping for the variable or return the original value as a fallback
    variable = AKAMAI_TO_AZION_MAP.get(value, value).strip()
    return variable

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
        value = map_variable(variable)
        return value

    # Replace all occurrences of Akamai variables in the string using the regex pattern
    modified_string = re.sub(pattern, replace_match, input_string)

    # Return the modified string, or the original if no replacements were made
    value = modified_string if modified_string != input_string else input_string
    return value

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
        "IS_NOT_ONE_OF", "IS_NOT"
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

def format_file_extension_pattern(values: Union[List[str], str]) -> str:
    """
    Formats a list of file extensions into a regex pattern for matching file extensions.
    
    Args:
        values: List of file extensions or a single extension string.
                Special value "EMPTY_STRING" can be used to match URLs without file extensions.
        
    Returns:
        str: Regex pattern that matches any of the provided file extensions or URLs without extensions
             when "EMPTY_STRING" is included.
    """
    if isinstance(values, str):
        values = [values]
    
    # Separate regular extensions from the special EMPTY_STRING
    extensions = [v for v in values if v != "EMPTY_STRING"]
    has_empty_string = "EMPTY_STRING" in values
    
    patterns = []
    
    # Add pattern for URLs with extensions
    if extensions:
        # Escape special regex characters in extensions
        escaped_extensions = [re.escape(ext) for ext in extensions]
        ext_pattern = r"\\.({})(\\?.*)?$".format("|".join(escaped_extensions))
        patterns.append(ext_pattern)
    
    # Add pattern for URLs without extensions (EMPTY_STRING case)
    if has_empty_string:
        no_ext_pattern = r"^([^?#]\\/)?[^\\/\\.?#]+\\/?([?#].*)?$"
        patterns.append(no_ext_pattern)

    # Combine all patterns with OR (|)
    if patterns:
        return "|".join(f"({p})" for p in patterns)
    else:
        return r"(\\?.*)?$"  # Default fallback

def format_header_name(options: Dict[str, Any]) -> str:
    """
    Builds an HTTP header string in the format 'HeaderName: HeaderValue'

    Args:
        options (dict): Dictionary containing 'customHeaderName' and 'newHeaderValue' keys.

    Returns:
        str: Formatted header string in the form 'HeaderName:HeaderValue'.
    """
    envvar = options.get("context", {}).get("envvar")
    header_name = options.get('customHeaderName', '').strip()
    if header_name == '':
        header_name = HTTP_HEADERS.get(options.get('standardModifyHeaderName',''), '')
        if header_name == '':
            header_name = HTTP_HEADERS.get(options.get('standardDeleteHeaderName',''), '')
    header_value = map_variable(options.get('newHeaderValue', '').strip())

    if header_value == '':
        header_value = options.get('headerValue','')

    if envvar and header_value == envvar.get('target', ''):
        header_value = envvar.get('value', '')

    if header_value == '':
        return f"\"{header_name}\""
    return f"\"{header_name}: {header_value}\""


def format_path_pattern(values: List[str]) -> str:
    """
    Formats a list of uri path patterns into a double-escaped regex pattern.
    
    Args:
        values (List[str]): List of path patterns to format.
    
    Returns:
        str: Double-escaped regex pattern.
    """
    def escape_and_convert(pattern: str) -> str:
        if pattern.startswith('^'):
            pattern = pattern[1:]
        pattern = pattern.rstrip('\r')
        pattern = pattern.replace('*', '__WILDCARD__')
        escaped = re.escape(pattern).replace('__WILDCARD__', '.*')

        escaped = escaped.replace('/', r'\\/')
        escaped = escaped.replace(r'\.', r'\\.')
        escaped = escaped.replace(r'\-', r'\\-')
        escaped = escaped.replace(r'\&', r'\\&')
        escaped = escaped.replace(r'\?', r'\\?')
        escaped = escaped.replace(r'\d', r'\\d')
        return escaped

    joined = "|".join(escape_and_convert(v) for v in values)
    return rf"^({joined})$"

def format_filename_pattern(values: List[str]) -> str:
    """
    Formats a list of uri path patterns into a double-escaped regex pattern.
    
    Args:
        values (List[str]): List of path patterns to format.
    
    Returns:
        str: Double-escaped regex pattern.
    """
    def escape_and_convert(pattern: str) -> str:
        if pattern.startswith('^'):
            pattern = pattern[1:]
        escaped = pattern.rstrip('\r')

        escaped = escaped.replace('/', r'\\/')
        escaped = escaped.replace(r'.', r'\\.')
        escaped = escaped.replace(r'-', r'\\-')
        return escaped

    joined = "|".join(escape_and_convert(v) for v in values)
    return rf"(.*)({joined})$"


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
    #Handle envvar
    envvar_startwith_slash = False
    envvar = options.get("context", {}).get("envvar")
    if envvar:
        if envvar.get('target').strip() == '/':
            envvar['value'] = '/'
        envvar_startwith_slash = envvar.get('target','').strip().startswith('/')
    path = None

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
        path = f"{prefix}/$${{uri}}{suffix}"
        query_string = '$${args}' if options.get('queryString') == 'APPEND' else ''
    elif path_type == 'OTHER':
        value = options.get('destinationPathOther')
        other_path = replace_variables(value)
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
        if not path.startswith('/') and not envvar_startwith_slash:
            path = '/' + path
        url = f"{url}{path}"
    if query_string and '?' not in url:
        url = f"{url}?{query_string}"
    
    return f'"{url}"'

def get_http_header_varname(options: Dict[str, Any]) -> str:
    """
    Returns the variable name from the options dictionary, removing the 'PMUSER_' prefix if present.
    """
    varname = options.get("variableName", "NONE")
    if "PMUSER_" in varname:
        varname = varname.removeprefix('PMUSER_')
    return f'$${{http_{sanitize_name(varname)}}}'
    
def format_varitens_pattern(itens: List[str]) -> str:
    """
    Returns the variable values from the options dictionary
    """
    regex = '({})'.format("|".join(itens))
    return regex

def filter_rules_engine_by_phase(rules, target_phase):
    """
    Filters a list of rules engines by the given phase.

    Parameters:
    - rules: list of dictionaries containing rules engines.
    - target_phase: string indicating the desired phase (e.g., 'request').

    Returns:
    - A list of rules where the 'phase' field matches the target_phase.
    """
    return [rule for rule in rules if rule.get('phase') == target_phase]


def chain_rule_engine_dependencies(rules, order='asc', preserve_existing=True):
    """
    Sort rules by 'order' and add a dependency on the previous rule,
    formatted as 'azion_edge_application_rule_engine.<rule_name>'.
    Preserves existing valid dependencies while removing circular ones.

    Parameters:
    - rules: list of dictionaries representing the rules.
    - order: 'asc' (default) or 'desc' for sorting.
    - preserve_existing: if True, preserves existing non-circular dependencies.

    Returns:
    - List of rules with consistent, safe dependencies.
    """
    # Input validation
    if not isinstance(rules, list):
        raise TypeError("Parameter 'rules' must be a list.")
    
    if order not in ('asc', 'desc'):
        raise ValueError("Parameter 'order' must be 'asc' or 'desc'.")
    
    if not rules:
        return []

    # Sort rules based on 'order' field
    try:
        sorted_rules = sorted(
            rules, 
            key=lambda r: r.get('order', 0) if isinstance(r, dict) else 0, 
            reverse=(order == 'desc')
        )
    except (TypeError, KeyError) as e:
        raise ValueError(f"Error sorting rules: {e}") from e

    # Create mapping of rule names for quick lookup
    rule_names = {rule.get('name') for rule in sorted_rules if isinstance(rule, dict) and rule.get('name')}
    
    # Process each rule
    for i, rule in enumerate(sorted_rules):
        if not isinstance(rule, dict):
            continue
            
        name = rule.get('name')
        if not name or not isinstance(name, str):
            continue

        attributes = rule.setdefault('attributes', {})
        existing_deps = attributes.get('depends_on', [])
        
        # Ensure depends_on is a list and create a copy
        if not isinstance(existing_deps, list):
            existing_deps = []
        else:
            existing_deps = existing_deps.copy()

        cleaned_deps = []
        
        if preserve_existing:
            # Remove self-dependencies and dependencies on non-existent rules
            self_ref = f'azion_edge_application_rule_engine.{name}'
            
            for dep in existing_deps:
                if dep == self_ref:
                    continue
                
                # Extract rule name from dependency
                if dep.startswith('azion_edge_application_rule_engine.'):
                    dep_rule_name = dep.split('.')[-1]
                    # Only keep if the target rule exists
                    if dep_rule_name in rule_names:
                        cleaned_deps.append(dep)
                else:
                    # Keep non-azion dependencies as-is
                    cleaned_deps.append(dep)

        # Add dependency on previous rule if not first
        if i > 0:
            prev_rule = sorted_rules[i - 1]
            if isinstance(prev_rule, dict):
                prev_name = prev_rule.get('name')
                if prev_name and isinstance(prev_name, str) and prev_name != name:
                    prev_ref = f'azion_edge_application_rule_engine.{prev_name}'
                    if prev_ref not in cleaned_deps:
                        cleaned_deps.append(prev_ref)

        attributes['depends_on'] = cleaned_deps

    return sorted_rules


def detect_and_resolve_circular_dependencies(rules):
    """
    Detect circular dependencies and resolve them by removing problematic ones.
    
    Parameters:
    - rules: list of rule dictionaries
    
    Returns:
    - tuple: (rules_with_cycles_removed, removed_dependencies, remaining_cycles)
    """
    import copy
    
    # Work with a deep copy to avoid modifying original
    working_rules = copy.deepcopy(rules)
    removed_deps = []
    max_iterations = len(rules) * 2  # Prevent infinite loops
    iteration = 0
    
    while iteration < max_iterations:
        cycles = detect_circular_dependencies(working_rules)
        
        if not cycles:
            break  # No more cycles found
        
        # Remove one dependency from the first cycle found
        cycle = cycles[0]
        if len(cycle) >= 2:
            # Remove dependency from last rule in cycle to first rule
            last_rule_ref = cycle[-2]  # Second to last (before the repeat)
            first_rule_ref = cycle[0]
            
            # Find the rule and remove the problematic dependency
            for rule in working_rules:
                if not isinstance(rule, dict):
                    continue
                
                rule_name = rule.get('name')
                if not rule_name:
                    continue
                
                rule_ref = f'azion_edge_application_rule_engine.{rule_name}'
                
                if rule_ref == last_rule_ref:
                    depends_on = rule.get('attributes', {}).get('depends_on', [])
                    if first_rule_ref in depends_on:
                        depends_on.remove(first_rule_ref)
                        removed_deps.append((last_rule_ref, first_rule_ref))
                        print(f"🔧 Removida dependência circular: {rule_name} → {first_rule_ref.split('.')[-1]}")
                        break
        
        iteration += 1
    
    # Check if any cycles remain
    final_cycles = detect_circular_dependencies(working_rules)
    
    return working_rules, removed_deps, final_cycles


def detect_circular_dependencies(rules):
    """
    Detect circular dependencies in rules.
    
    Parameters:
    - rules: list of rule dictionaries
    
    Returns:
    - list of lists representing circular dependency paths
    """
    dependencies = {}
    
    # Build dependency graph
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        
        name = rule.get('name')
        if not name:
            continue
            
        rule_ref = f'azion_edge_application_rule_engine.{name}'
        depends_on = rule.get('attributes', {}).get('depends_on', [])
        
        # Filter only azion rule dependencies
        azion_deps = [dep for dep in depends_on 
                     if isinstance(dep, str) and dep.startswith('azion_edge_application_rule_engine.')]
        
        dependencies[rule_ref] = azion_deps
    
    # Find cycles using DFS
    def find_cycles():
        visited = set()
        rec_stack = set()
        cycles = []
        
        def dfs(node, path):
            if node in rec_stack:
                # Found cycle
                cycle_start = path.index(node)
                cycle = path[cycle_start:] + [node]
                cycles.append(cycle)
                return
            
            if node in visited:
                return
            
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            
            for neighbor in dependencies.get(node, []):
                if neighbor in dependencies:  # Only follow if target exists
                    dfs(neighbor, path)
            
            rec_stack.remove(node)
            path.pop()
        
        for node in dependencies:
            if node not in visited:
                dfs(node, [])
        
        return cycles
    
    return find_cycles()


def smart_chain_rule_engine_dependencies(rules, order='asc', strategy='preserve_and_fix'):
    """
    Intelligently chain rule dependencies with multiple strategies.
    
    Parameters:
    - rules: list of rule dictionaries
    - order: 'asc' or 'desc' for sorting
    - strategy: 'preserve_and_fix', 'clean_slate', or 'minimal_changes'
    
    Returns:
    - tuple: (processed_rules, report)
    """
    report = {
        'original_cycles': [],
        'removed_dependencies': [],
        'final_cycles': [],
        'preserved_dependencies': 0,
        'added_dependencies': 0
    }
    
    # Detect initial cycles
    original_cycles = detect_circular_dependencies(rules)
    report['original_cycles'] = original_cycles
    
    if strategy == 'preserve_and_fix':
        if original_cycles:
            print(f"🔍 Detectadas {len(original_cycles)} dependências circulares")
            
            # Remove circular dependencies first
            rules_no_cycles, removed_deps, remaining_cycles = detect_and_resolve_circular_dependencies(rules)
            report['removed_dependencies'] = removed_deps
            
            if remaining_cycles:
                print(f"⚠️  {len(remaining_cycles)} dependências circulares não puderam ser resolvidas automaticamente")
                report['final_cycles'] = remaining_cycles
            else:
                print("✅ Todas as dependências circulares foram resolvidas")
        else:
            rules_no_cycles = rules
        
        # Count existing dependencies before processing
        existing_deps = sum(len(rule.get('attributes', {}).get('depends_on', [])) 
                          for rule in rules_no_cycles if isinstance(rule, dict))
        
        # Apply chaining while preserving existing dependencies
        processed_rules = chain_rule_engine_dependencies(rules_no_cycles, order, preserve_existing=True)
        
        # Count dependencies after processing
        final_deps = sum(len(rule.get('attributes', {}).get('depends_on', [])) 
                        for rule in processed_rules if isinstance(rule, dict))
        
        report['preserved_dependencies'] = existing_deps - len(report['removed_dependencies'])
        report['added_dependencies'] = final_deps - existing_deps + len(report['removed_dependencies'])
    
    elif strategy == 'clean_slate':
        processed_rules = chain_rule_engine_dependencies(rules, order, preserve_existing=False)
        report['added_dependencies'] = len(processed_rules) - 1  # Chain adds n-1 dependencies
    
    elif strategy == 'minimal_changes':
        # Only add chain dependencies, don't remove anything unless circular
        if original_cycles:
            rules_no_cycles, removed_deps, _ = detect_and_resolve_circular_dependencies(rules)
            report['removed_dependencies'] = removed_deps
            processed_rules = chain_rule_engine_dependencies(rules_no_cycles, order, preserve_existing=True)
        else:
            processed_rules = chain_rule_engine_dependencies(rules, order, preserve_existing=True)
    
    return processed_rules, report

def merge_criteria(current_criteria, parent_criteria):
    """
    Merge `criterias` into `combined_criteria`.
    If a key exists in both dictionaries and both have an 'entries' list, the lists are concatenated.
    If a key exists only in `parent_criteria`, it is added to the result.

    Returns a new merged dictionary.
    """
    if not isinstance(current_criteria, dict):
        raise ValueError("current_criteria must be a dict")
    if not isinstance(parent_criteria, dict):
        parent_criteria = {}  # treat None as empty dict

    merged = copy.deepcopy(current_criteria)

    for key, value in parent_criteria.items():
        if key not in merged:
            merged[key] = copy.deepcopy(value)
        else:
            if isinstance(merged[key], dict) and 'entries' in merged[key] and 'entries' in value:
                existing_entries = {frozenset(entry.items()) for entry in merged[key]['entries']}
                for entry in value['entries']:
                    entry_key = frozenset(entry.items())
                    if entry_key not in existing_entries:
                        merged[key]['entries'].append(entry)
                        existing_entries.add(entry_key)
            else:
                raise ValueError(f"Conflict merging key '{key}': unexpected structure.")

    return merged


def normalize_conditionals(entries, criteria_has_condition="all"):
    """
    Deep copies and normalizes the 'conditional' field for a list of criteria entries.
    
    Parameters:
    - entries (list): List of entry dictionaries.
    - criteria_has_condition (str): 'all' sets conditionals to 'and' (after the first), 
                                    otherwise uses 'or'.
    
    Returns:
    - list: A new list with modified entries.
    """
    normalized = []
    for index, entry in enumerate(entries):
        entry_copy = copy.deepcopy(entry)
        if index == 0:
            entry_copy["conditional"] = "if"
        else:
            entry_copy["conditional"] = "and" if criteria_has_condition == "all" else "or"
        normalized.append(entry_copy)
    return normalized
