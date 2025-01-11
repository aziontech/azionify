import logging
import random
from typing import Dict, List, Any, Set, Tuple
from azion_resources import AzionResource
from akamai.mapping import MAPPING
from akamai.utils import map_forward_host_header, map_origin_type, replace_variables, map_operator
from utils import sanitize_name

default_criteria = {
    "name": "default",
    "variable": "$${uri}",
    "operator": "starts_with",
    "conditional": "if",
    "input_value": "/"
}

def create_rule_engine(azion_resources: AzionResource, rule: Dict[str, Any], context: Dict[str, Any], name: str = None) -> List[Dict[str, Any]]:
    """
    Create a rule engine resource from Akamai rule data.

    Parameters:
        azion_resources (AzionResource): Azion resource container
        rule (dict): Akamai rule data
        context (dict): Context variables
        name (str): Rule name

    Returns:
        dict: Azion rule engine resource
    """
    resources = []
    rule_name = name if name else rule.get("name", "Unnamed Rule")
    index = context.get("rule_index", 0)
    main_setting_name = context.get("main_setting_name", "unnamed")

    logging.info(f"[rules_engine] Processing rule: '{rule_name}' with index {index}")

    # Extract behaviors and criteria
    behaviors = rule.get("behaviors", [])
    criteria = rule.get("criteria", [])

    logging.info(f"[rules_engine] Found {len(behaviors)} behaviors and {len(criteria)} criteria for rule: '{rule_name}'")

    try:
        # Create resource if either behaviors or criteria exist
        if behaviors or criteria:
            # Process conditions
            processed_rule = process_conditional_rule(rule)

            # Process behaviors and criteria
            azion_behaviors, depends_on_behaviors = process_behaviors(azion_resources, behaviors, context, rule_name)
            behaviors_names = [behavior.get("name") for behavior in behaviors]
            azion_criteria = process_criteria(criteria, behaviors_names)

            # Handling depends_on
            depends_on = [f"azion_edge_application_main_setting.{main_setting_name}"]
            depends_on.extend(list(depends_on_behaviors))

            request_behaviors = list(filter(lambda behavior: behavior.get('phase', 'request') == 'request', azion_behaviors))
            response_behaviors = list(filter(lambda behavior: behavior.get('phase', 'request') == 'response', azion_behaviors))

            # Create request phase rule
            if len(request_behaviors) > 0:
                resource = assemple_request_rule(processed_rule, 
                                                rule_name, 
                                                main_setting_name, 
                                                azion_criteria, 
                                                request_behaviors, 
                                                depends_on)
                resources.append(resource)
                logging.info(f"[rules_engine] Rule engine resource created for rule: '{rule_name}'")

            # Create response phase rule
            if len(response_behaviors) > 0:
                for behavior in response_behaviors:
                    resource = assemple_response_rule(processed_rule, 
                                                rule_name, 
                                                main_setting_name, 
                                                azion_criteria, 
                                                behavior, 
                                                depends_on)
                    resources.append(resource)
                    logging.info(f"[rules_engine] Rule engine resource created for rule: '{rule_name}'")

            # Enable image optimization if necessary
            if "imageManager" in behaviors_names:
                idx, main_settings = azion_resources.query_azion_resource_by_type('azion_edge_application_main_setting')
                if main_settings:
                    az_resources = azion_resources.get_azion_resources()
                    main_settings["attributes"]["edge_application"]["image_optimization"] = True
                    az_resources[idx] = main_settings
        else:
            logging.warning(f"[rules_engine] No behaviors or criteria found for rule: '{rule_name}'. Skipping.")
    except ValueError as e:
        logging.error(f"[rules_engine] Error processing rule '{rule_name}': {str(e)}")

    return resources

def assemple_request_rule(rule: Dict[str, Any], rule_name: str, main_setting_name: str, azion_criteria: Dict[str, Any], request_behaviors: List[Dict[str, Any]], depends_on: List[str]) -> Dict[str, Any]:
    '''
    Create a rule engine resource from Akamai rule data.

    Parameters:
    rule (Dict[str, Any]): Akamai rule data.
    rule_name (str): Name of the rule.
    main_setting_name (str): Name of the main setting.
    azion_criteria (Dict[str, Any]): Criteria to be used in the rule.
    request_behaviors (List[Dict[str, Any]]): List of behaviors to be applied in the rule.
    depends_on (List[str]): List of dependencies for the rule.

    Returns:
    Dict[str, Any]: Rule engine resource.
    '''
    phase = "request" if rule_name != "default" else "default"
    resource = {
        "type": "azion_edge_application_rule_engine",
        "name": sanitize_name(rule_name), 
        "attributes": {
            "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.edge_application.application_id",
            "results": {
                "name": "Default Rule" if phase == "default" else sanitize_name(rule_name),
                "description": rule.get("comments", ""),
                "phase": phase,
                "behaviors": request_behaviors
            },
            "depends_on": depends_on
        }
    }

    # Only add criteria if we have entries
    if azion_criteria:
        criteria = azion_criteria.get("request",{}) if azion_criteria.get("request",{}) else azion_criteria.get("request_default",{})
        resource["attributes"]["results"]["criteria"] = criteria
    return resource


def assemple_response_rule(rule: Dict[str, Any], rule_name: str, main_setting_name: str, azion_criteria: Dict[str, Any], behavior: Dict[str, Any], depends_on: List[str]) -> Dict[str, Any]:
    '''
    Create a rule engine resource from Akamai rule data.

    Parameters:
    rule (Dict[str, Any]): Akamai rule data.
    rule_name (str): Name of the rule.
    main_setting_name (str): Name of the main setting.
    azion_criteria (Dict[str, Any]): Criteria to be used in the rule.
    response_behaviors (List[Dict[str, Any]]): List of behaviors to be applied in the rule.
    depends_on (List[str]): List of dependencies for the rule.

    Returns:
    Dict[str, Any]: Rule engine resource.
    '''
    
    name = sanitize_name(f"{rule_name}_{behavior.get('name')}")

    # Find criteria for the behavior
    criterias = azion_criteria.get("response",{}).get("entries",None)
    if criterias:
        if len(criterias) == 1:
            selected_criteria = azion_criteria.get("response")
        else:
            for criteria in criterias:
                if criteria.get("name", "") == behavior.get('name'):
                    selected_criteria = {"entries": [criteria]}
                    break
    else:
        selected_criteria = azion_criteria.get("response_default")
    
    resource = {
        "type": "azion_edge_application_rule_engine",
        "name": name,
        "attributes": {
            "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.edge_application.application_id",
            "results": {
                "name": behavior.get("name"),
                "description": rule.get("comments", ""),
                "phase": "response",
                "behaviors": [behavior]
            },
            "depends_on": depends_on
        }
    }

    # Only add criteria if we have entries
    if selected_criteria:
        resource["attributes"]["results"]["criteria"] = selected_criteria
    return resource

def process_conditional_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process rules with conditions and create Azion-compatible conditions.
    
    Parameters:
        rule (dict): The rule to process.
    
    Returns:
        dict: Processed rule with Azion-compatible conditions.
    """
    processed_rule = rule.copy()
    conditions = rule.get("criteria", [])
    
    if not conditions:
        return processed_rule

    azion_conditions = []
    for condition in conditions:
        condition_name = condition.get("name", "")
        if condition_name in MAPPING.get("criteria", {}):
            mapping = MAPPING["criteria"][condition_name]

            # Handle content type criteria specially
            if condition_name == "contentType":
                content_types = condition.get("options", {}).get("values", [])
                if content_types:
                    azion_conditions.append({
                        "conditional": mapping["azion_condition"],
                        "operator": mapping["azion_operator"],
                        "input_value": "|".join(content_types)  # Join multiple content types with OR operator
                    })
            else:
                # Handle other criteria types
                azion_conditions.append({
                    "conditional": mapping["azion_condition"],
                    "operator": mapping["azion_operator"],
                    "input_value": condition.get("options", {}).get("value", "")
                })
        else:
            logging.warning(f"Unmapped condition: {condition_name}")
            
    if azion_conditions:
        processed_rule["criteria"] = azion_conditions
        
    return processed_rule

def process_criteria_default(behaviors_names: List[str]) -> Dict[str, Any]:
    azion_criteria = {}
    request_entries = []
    response_entries = []

    # Default criteria for when no criteria is defined
    for behavior_name in behaviors_names:
        mapping = MAPPING.get("criteria", {}).get(behavior_name)
        
        if mapping:
            
            entry = {
                "name": mapping.get("name",behavior_name),
                "variable": mapping.get("azion_condition"),
                "operator": mapping.get("azion_operator"),
                "conditional": mapping.get("conditional"),
                "phase": mapping.get("phase","request"),
                "akamai_behavior": mapping.get("akamai_behavior",""),
            }
            if mapping.get("azion_operator"):
                entry["input_value"] = mapping.get("input_value")

            # Append to the correct phase
            if mapping.get("phase") == "response":
                response_entries.append(entry)
            else:
                request_entries.append(entry)

    azion_criteria["request_default"] = {"entries":[default_criteria]}
    azion_criteria["response_default"] = {"entries":[default_criteria]}
    if len(request_entries) > 0:
        azion_criteria["request"] = {"entries": request_entries}
        logging.info("No criteria found for request phase of the rule, using default criterias based on the behaviors")
    if len(response_entries) > 0:
        azion_criteria["response"] = {"entries": response_entries}
        logging.info("No criteria found for response phase of the rule, using default criterias based on the behaviors")   
    return azion_criteria

def process_criteria(criteria: List[Dict[str, Any]], behaviors_names: List[str]) -> List[Dict[str, Any]]:
    """
    Processes and maps Akamai criteria to Azion-compatible criteria.

    Parameters:
        criteria (List[Dict[str, Any]]): List of Akamai criteria.
        behaviors_names (List[str]): List of behavior names.

    Returns:
        List[Dict[str, Any]]: List of Azion criteria grouped by phase.
    """
    azion_criteria = {}
    request_entries = []
    response_entries = []

    if not criteria:
        azion_criteria = process_criteria_default(behaviors_names)
        return azion_criteria

    # Map Akamai's criteriaMustSatisfy to Azion's conditional
    criteria_must_satisfy = criteria[0].get("criteriaMustSatisfy", "one")
    conditional_map = {
        "all": "and",
        "any": "or",
        "one": "if"
    }
    group_conditional = conditional_map.get(criteria_must_satisfy, "and")

    for index, criterion in enumerate(criteria):
        name = criterion.get("name")
        options = criterion.get("options", {})

        if not name:
            logging.warning(f"Criterion at index {index} is missing a name. Skipping.")
            continue

        mapping = MAPPING.get("criteria", {}).get(name)
        if not mapping:
            logging.warning(f"No mapping found for criterion: {name}. Skipping.")
            continue

        try:
            # Map operator
            akamai_operator = options.get("matchOperator", "EQUALS")
            azion_operator = map_operator(akamai_operator)

            # Handle input values
            values = options.get("values", [])
            if isinstance(values, str):
                values = [values]

            # Handle single or multiple values based on the operator
            if azion_operator in {"exists", "does_not_exist"}:
                input_value = None
            else:
                if callable(mapping.get("input_value")):
                    input_value = mapping["input_value"](values)
                elif values:
                    input_value = values[0]
                else:
                    input_value = "*"

            # Build the entry
            entry = {
                "variable": mapping["azion_condition"],
                "operator": azion_operator,
                "conditional": group_conditional,
                "akamai_behavior": mapping.get("akamai_behavior",""),
            }
            if input_value is not None:
                entry["input_value"] = input_value

            # Append to the correct phase
            if mapping.get("phase") == "response":
                response_entries.append(entry)
            elif mapping.get("phase") == "request":
                request_entries.append(entry)
            else:
                response_entries.append(entry)
                request_entries.append(entry)

        except ValueError as e:
            logging.error(f"Error processing criterion {name}: {str(e)}")

    # Assemble criteria groups
    if request_entries:
        azion_criteria["request"] = {"entries": request_entries}
    if response_entries:
        azion_criteria["response"] = {"entries": response_entries}

    return azion_criteria

def behavior_cache_setting(context: Dict[str, Any], azion_resources: AzionResource, options: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """
    Handles cache settings dependencies for a behavior.

    Parameters:
        context (dict): The context dictionary containing rule information.
        azion_resources (AzionResource): The Azion resource container.
        options (dict): The options dictionary containing cache settings information.

    Returns:
        tuple: A tuple containing the Azion behavior and cache settings reference.
    """

    azion_behavior = None
    cache_settings_ref = None

    parent_rule_name = context.get("parent_rule_name", None)
    rule_name = context.get("rule_name", None)

    # Handle cache settings dependencies
    cache_setttings = context.get("cache_setting", None)
    if cache_setttings is None:
        _, cache_setttings = azion_resources.query_azion_resource_by_type(
            'azion_edge_application_cache_setting', sanitize_name(parent_rule_name))
        if cache_setttings is None:
            _, cache_setttings = azion_resources.query_azion_resource_by_type(
                'azion_edge_application_cache_setting', sanitize_name(rule_name))

    if cache_setttings:
        cache_settings_name = cache_setttings.get("name")
        cache_settings_ref = f'azion_edge_application_cache_setting.{cache_settings_name}'

        azion_behavior = {
            "name": "set_cache_policy",
            "enabled": True,
            "target": {"target": cache_settings_ref + ".id"},
            "description": f"Set cache policy to {options.get('name', '')}",
            "phase": "request"
        }
    return azion_behavior, cache_settings_ref

def behavior_set_origin(context: Dict[str, Any], azion_resources: AzionResource, options: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """
    Handles origin settings dependencies for a behavior.

    Parameters:
        context (dict): The context dictionary containing rule information.
        azion_resources (AzionResource): The Azion resource container.
        options (dict): The options dictionary containing origin settings information.

    Returns:
        tuple: A tuple containing the Azion behavior and origin settings reference.
    """

    azion_behavior = None
    origin_settings_ref = None

    rule_name = context.get("rule_name", None)
    parent_rule_name = context.get("parent_rule_name", "unamed")

    # Handle origin settings dependencies
    origin_settings = context.get("origin", None)
    if origin_settings is None:
        _, origin_settings = azion_resources.query_azion_resource_by_type(
        "azion_edge_application_origin",
        sanitize_name(parent_rule_name))
        if origin_settings is None:
            _, origin_settings = azion_resources.query_azion_resource_by_type(
                "azion_edge_application_origin",
                sanitize_name(rule_name))
            if origin_settings is None:
                origin_settings = azion_resources.query_azion_origin_by_address(options.get("hostname", ""))

    if origin_settings:
        origin_settings_name = origin_settings.get("name")
        origin_settings_ref = f'azion_edge_application_origin.{origin_settings_name}'

        azion_behavior = {
            "name": "set_origin",
            "enabled": True,
            "target": {"target": origin_settings_ref + ".id"},
            "description": f"Set origin to {options.get('name', '')}",
        }

    return azion_behavior, origin_settings_ref

def behavior_capture_match_groups(context: Dict[str, Any], azion_resources: AzionResource, options: Dict[str, Any], mapping: Dict[str, Any], behavior: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """
    Handles capture match groups dependencies for a behavior.

    Parameters:
        context (dict): The context dictionary containing rule information.
        azion_resources (AzionResource): The Azion resource container.
        options (dict): The options dictionary containing capture match groups information.

    Returns:
        tuple: A tuple containing the Azion behavior and capture match groups reference.
    """

    azion_behavior = None

    required_fields = {
        "captured_array": options.get("variableName"),
        "regex": options.get("regex")
    }
    missing_fields = {k: v for k, v in required_fields.items() if not v}
    if missing_fields:
        logging.warning(f"Behavior '{mapping['azion_behavior']}' is missing required fields: {missing_fields}")
        return azion_behavior, None

    regex_value = replace_variables(options.get('regex')).replace('/', r'\\/').replace('.', r'\\.')
    random_number = random.randint(1000, 9999)
    captured_array = options.get("variableName",f"var{random_number}")[:10]
    azion_behavior = {
        "name": mapping["azion_behavior"],
        "enabled": True,
        "description": behavior.get("description", "Behavior capture_match_groups, variableName: " + options.get("variableName", "")),
        "target": {
            "captured_array": f'"{captured_array}"',
            "subject": f'{replace_variables(options.get("variableValue"))}',
            "regex": f"\"(.*)\\\\/{regex_value}\"",
        }
    }

    return azion_behavior, None


def process_behaviors(azion_resources: AzionResource,behaviors: List[Dict[str, Any]], context: Dict[str, Any], rule_name: str, parent_rule_name: str = None) -> Tuple[List[Dict[str, Any]], Set[str]]:
    """
    Process and map Akamai behaviors to Azion-compatible behaviors.

    Parameters:
        behaviors (list): List of Akamai behaviors.

    Returns:
        tuple: Tuple containing a list of Azion-compatible behaviors and a set of dependencies.
    """
    if not behaviors:
        return [], set()

    azion_behaviors = []
    seen_behaviors = set()  # Track unique behaviors
    cache_policy_options = {}  # Collect all cache policy related options
    depends_on = set()
    parent_rule_name = context.get("parent_rule_name", rule_name)

    logging.info(f"[rules_engine][process_behaviors] Rule = '{rule_name}', Parent rule = '{parent_rule_name}'")
    logging.info(f'[rules_engine][process_behaviors] Processing {len(behaviors)} behaviors')

    for behavior in behaviors:
        ak_behavior_name = behavior.get("name")
        if not ak_behavior_name or ak_behavior_name not in MAPPING.get("behaviors", {}):
            logging.warning(f"[rules_engine][process_behaviors] Unmapped behavior: {ak_behavior_name}")
            logging.debug(f"[rules_engine][process_behaviors] Behavior options: {behavior.get('options', {})}")
            continue

        mapping = MAPPING["behaviors"][ak_behavior_name]
        options = behavior.get("options", {})

        # Handle behavior name
        if callable(mapping.get("azion_behavior")):
            try:
                behavior_name = mapping["azion_behavior"](options)
            except ValueError as e:
                logging.error(f"[rules_engine][process_behaviors] Error processing azion_behavior in behavior '{ak_behavior_name}': {e}")
        else:
            behavior_name = mapping["azion_behavior"]

        logging.info(f"[rules_engine][process_behaviors] Mapping from '{ak_behavior_name}' to '{behavior_name}'")

        # Skip behaviors that are explicitly disabled
        if "enabled" in options and options["enabled"] is False:
            logging.debug(f"[rules_engine][process_behaviors] Behavior '{behavior_name}' is explicitly disabled. Skipping.")
            continue

        # Handle special behavior: set_cache_policy
        if mapping["azion_behavior"] == "set_cache_policy":
            # Unique key for set_cache_policy
            if "set_cache_policy" in seen_behaviors:
                continue

            azion_behavior, cache_settings_ref = behavior_cache_setting(context, azion_resources, options)
            if azion_behavior:
                depends_on.add(cache_settings_ref)
                azion_behaviors.append(azion_behavior)
                seen_behaviors.add("set_cache_policy")
            else:
                logging.debug(f"[rules_engine][process_behaviors] Cache settings not found for rule '{rule_name}'. Skipping.")
            continue

        # Handle special behavior: set_origin
        if mapping["azion_behavior"] == "set_origin":
            # Unique key for set_origin
            if "set_origin" in seen_behaviors:
                continue

            azion_behavior, origin_settings_ref = behavior_set_origin(context, azion_resources, options)
            if azion_behavior:
                azion_behaviors.append(azion_behavior)
                seen_behaviors.add("set_origin")
                depends_on.add(origin_settings_ref)
            else:
                logging.debug(f"[rules_engine][process_behaviors] Origin settings not found for rule '{rule_name}'. Skipping.")
                continue

            # Handle compression
            if options.get("compress", True):
                # Unique key for enable_gzip
                if "origin_enable_gzip" in seen_behaviors:
                    continue

                azion_behavior = {
                    "name": "enable_gzip",
                    "enabled": True,
                    "description": "Compress content",
                    "target": {},
                }
                azion_behaviors.append(azion_behavior)
                seen_behaviors.add("origin_enable_gzip")

            # Handle true client ip (add_request_header)
            if options.get("enableTrueClientIp", False) == True:
                trueClientIpHeader = options.get("trueClientIpHeader", "")
                if trueClientIpHeader:
                    # Unique key for add_request_header
                    if "origin_add_request_header" in seen_behaviors:
                        continue

                    azion_behavior = {
                        "name": "add_request_header",
                        "enabled": True,
                        "description": f"Add host header to {trueClientIpHeader}",
                        "target": { "target": '"' + f'{trueClientIpHeader}: ' + "$${remote_addr}" + '"' },
                    }
                    azion_behaviors.append(azion_behavior)
                    seen_behaviors.add("origin_add_request_header")
            continue
        

        # Handle special behavior: set_host_header
        if mapping["azion_behavior"] == "set_host_header":
            # Unique key for set_host_header
            if "set_host_header" in seen_behaviors:
                continue

            host_header = map_forward_host_header(options)
            azion_behavior = {
                "name": "set_host_header",
                "enabled": True,
                "description": behavior.get("description", f"Set host header to {host_header}"),
                "target": { "host_header": host_header },
                "phase": "request"
            }
            azion_behaviors.append(azion_behavior)
            seen_behaviors.add("set_host_header")
            continue

        # Handle special behavior: capture_match_groups
        if mapping["azion_behavior"] == "capture_match_groups":
            azion_behavior, _ = behavior_capture_match_groups(context, azion_resources, options, mapping, behavior)
            if azion_behavior:
                # Create a unique key to track this behavior
                unique_key = (azion_behavior["name"], tuple(sorted(azion_behavior.get("target", {}).items())))
                if unique_key in seen_behaviors:
                    logging.debug(f"[rules_engine][process_behaviors] Duplicate behavior detected: {unique_key}. Skipping.")
                    continue

                azion_behaviors.append(azion_behavior)
                seen_behaviors.add(unique_key)
            continue

        # Skip if we've already processed this behavior type
        if behavior_name in seen_behaviors:
            logging.debug(f"Behavior '{behavior_name}' already processed. Skipping.")
            continue

        azion_behavior = {
            "name": behavior_name,
            "enabled": behavior.get("options", {}).get("enabled", True),
            "description": behavior.get("description", f"Behavior for {behavior_name}"),
            "phase": mapping.get("phase", "request")
        }

        # Process target if present
        if "target" in mapping:
            target = {}
            if isinstance(mapping["target"], dict):
                for target_key, option_key in mapping["target"].items():
                    try:
                        value = option_key(options) if callable(option_key) else options.get(option_key)
                        if value is not None:
                            target[target_key] = value
                        else:
                            target[target_key] = f'"{option_key}"'
                    except ValueError as e:
                        logging.error(f"[rules_engine][process_behaviors] Error processing target for key '{target_key}' in behavior '{behavior_name}': {e}")
            elif isinstance(mapping["target"], str):
                try:
                    value = options.get(mapping["target"])
                    if value is not None:
                        target = value
                except ValueError as e:
                    logging.error(f"[rules_engine][process_behaviors] Error accessing target for behavior '{behavior_name}': {e}")

            # Special handling for origin
            if behavior_name == "set_origin":
                target["origin_type"] = map_origin_type(options.get("originType", "CUSTOMER"))

            if target:  # Only add target if we have values
                azion_behavior["target"] = target

        azion_behaviors.append(azion_behavior)
        seen_behaviors.add(behavior_name)

    # Add consolidated cache policy if we collected any optionss
    if cache_policy_options:
        azion_behaviors.append({
            "name": "set_cache_policy",
            "enabled": True,
            "target": cache_policy_options,
            "description": "Cache policy consolidated from multiple behaviors"
        })

    return azion_behaviors, depends_on