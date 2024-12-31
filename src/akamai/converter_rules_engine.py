import logging
from typing import Dict, List, Any, Set, Tuple
from azion_resources import AzionResource
from akamai.mapping import MAPPING
from akamai.utils import map_forward_host_header, map_origin_type, replace_variables, map_operator
from utils import sanitize_name

default_criteria = {
    "variable": "$${uri}",
    "operator": "starts_with",
    "conditional": "if",
    "input_value": "/"
}

def create_rule_engine(azion_resources: AzionResource, rule: Dict[str, Any], main_setting_name: str, index: int, parent_rule_name: str = None, name: str = None) -> List[Dict[str, Any]]:
    """
    Create a rule engine resource from Akamai rule data.

    Parameters:
        rule (dict): Akamai rule data
        main_setting_name (str): Edge application ID
        index (int): Rule index for priority calculation

    Returns:
        dict: Azion rule engine resource
    """
    resources = []
    rule_name = name if name else rule.get("name", "Unnamed Rule")

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
            
            # Calculate priority based on position and settings
            priority = process_rule_priority(processed_rule, index)

            # Process behaviors and criteria
            azion_behaviors, depends_on_behaviors = process_behaviors(azion_resources, behaviors, rule_name, parent_rule_name)
            azion_criteria = process_criteria(criteria)

            # Handling depends_on
            depends_on = [f"azion_edge_application_main_setting.{main_setting_name}"]
            depends_on.extend(list(depends_on_behaviors))

            if azion_behaviors or azion_criteria:  # Create rule if we have valid behaviors or criteria
                resource = {
                    "type": "azion_edge_application_rule_engine",
                    "name": sanitize_name(rule_name),
                    "attributes": {
                        "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.edge_application.application_id",
                        "results": {
                            "name": sanitize_name(rule_name),
                            "description": rule.get("comments", ""),
                            "phase": processed_rule.get("phase", "request"),
                            "behaviors": azion_behaviors
                        },
                        "depends_on": depends_on
                    }
                }

                # Only add criteria if we have entries
                if azion_criteria:
                    resource["attributes"]["results"]["criteria"] = azion_criteria

                resources.append(resource)
                logging.info(f"[rules_engine] Rule engine resource created for rule: '{rule_name}'")
        else:
            logging.warning(f"[rules_engine] No behaviors or criteria found for rule: '{rule_name}'. Skipping.")
    except ValueError as e:
        logging.error(f"[rules_engine] Error processing rule '{rule_name}': {str(e)}")

    return resources


def process_children(azion_resources: AzionResource,children: List[Dict[str, Any]], main_setting_name: str, parent_index: int, rule_name: str) -> List[Dict[str, Any]]:
    """
    Process child rules and create corresponding Azion resources.
    
    Parameters:
        children (list): List of child rules to process
        main_setting_name (str): Name of the main setting resource
        parent_index (int): Index of the parent rule for priority calculation
        
    Returns:
        list: List of processed Azion resources
    """
    resources = []
    child_priority_multiplier = 100

    for index, child in enumerate(children):
        try:
            logging.info(f"[process_children] Processing parent rule: '{rule_name}', child rule: '{child.get('name', 'unnamed')}'")
            normalized_name = sanitize_name(child.get("name", "unnamed"))
            # Calculate child priority based on parent index and child position
            child_index = (parent_index * child_priority_multiplier) + index
            resources.extend(create_rule_engine(azion_resources, child, main_setting_name, child_index, f'{rule_name}_{normalized_name}'))
        except ValueError as e:
            logging.error(f"[process_children] Error processing child rule '{child.get('name', 'unnamed')}': {str(e)}")
    return resources


def process_rule_priority(rule: Dict[str, Any], index: int) -> int:
    """
    Calculate rule priority based on position and custom settings.
    
    Parameters:
        rule (dict): The rule to process.
        index (int): Position of the rule in the sequence.
    
    Returns:
        int: Calculated priority value.
    """
    base_priority = index * 10
    custom_priority = rule.get("options", {}).get("priority", 0)
    
    if rule.get("criteriaMustSatisfy") == "all":
        custom_priority += 5 # Increase priority for rules with all criteria
        
    return base_priority + custom_priority


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

def process_criteria(criteria: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Processes and maps Akamai criteria to Azion-compatible criteria.

    Parameters:
        criteria (List[Dict[str, Any]]): List of Akamai criteria.

    Returns:
        List[Dict[str, Any]]: List of Azion criteria grouped by phase.
    """
    azion_criteria = []

    if not criteria:
        # Default criteria for when no criteria is defined
        azion_criteria.append({"entries": [default_criteria]})
        return azion_criteria

    # Map Akamai's criteriaMustSatisfy to Azion's conditional
    criteria_must_satisfy = criteria[0].get("criteriaMustSatisfy", "one")
    conditional_map = {
        "all": "and",
        "any": "or",
        "one": "if"
    }
    group_conditional = conditional_map.get(criteria_must_satisfy, "and")

    # Separate criteria into request and response phases
    request_entries = []
    response_entries = []

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
            }
            if input_value is not None:
                entry["input_value"] = input_value

            # Append to the correct phase
            if mapping.get("phase") == "response":
                response_entries.append(entry)
            else:
                request_entries.append(entry)

        except ValueError as e:
            logging.error(f"Error processing criterion {name}: {str(e)}")

    # Assemble criteria groups
    if request_entries:
        azion_criteria.append({"entries": request_entries})
    if response_entries:
        azion_criteria.append({"entries": response_entries})

    return azion_criteria

def process_behaviors(azion_resources: AzionResource,behaviors: List[Dict[str, Any]], rule_name: str, parent_rule_name: str = None) -> Tuple[List[Dict[str, Any]], Set[str]]:
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
        # Handle cache policy

        # Skip behaviors that are explicitly disabled
        if "enabled" in options and options["enabled"] is False:
            logging.debug(f"[rules_engine][process_behaviors] Behavior '{behavior_name}' is explicitly disabled. Skipping.")
            continue

        # Handle special behavior: set_cache_policy
        if mapping["azion_behavior"] == "set_cache_policy":
            # Unique key for set_cache_policy
            if "set_cache_policy" in seen_behaviors:
                continue

            # Handle cache settings dependencies
            # Try by parent_rule_name
            _, cache_setttings = azion_resources.query_azion_resource_by_type('azion_edge_application_cache_setting', sanitize_name(parent_rule_name))
            if not cache_setttings:
                # Try by rule_name
                _, cache_setttings = azion_resources.query_azion_resource_by_type('azion_edge_application_cache_setting', sanitize_name(rule_name))
            if cache_setttings:
                cache_settings_name = cache_setttings.get("name")
                cache_settings_ref = f'azion_edge_application_cache_setting.{cache_settings_name}'
                depends_on.add(cache_settings_ref)

                azion_behavior = {
                    "name": "set_cache_policy",
                    "enabled": True,
                    "target": {"target": cache_settings_ref + ".id"},
                    "description": f"Set cache policy to {options.get('name', '')}"
                }
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

            # Handle origin settings dependencies
            origin_settings = azion_resources.query_azion_origin_by_address(options.get("hostname", ""))
            if origin_settings:
                origin_settings_name = origin_settings.get("name")
                origin_settings_ref = f'azion_edge_application_origin.{origin_settings_name}'
                depends_on.add(origin_settings_ref)

                azion_behavior = {
                    "name": "set_origin",
                    "enabled": True,
                    "target": {"target": origin_settings_ref + ".id"},
                    "description": f"Set origin to {options.get('name', '')}"
                }
                azion_behaviors.append(azion_behavior)
                seen_behaviors.add("set_origin")
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
                    "target": {}
                }
                azion_behaviors.append(azion_behavior)
                seen_behaviors.add("origin_enable_gzip")

            # Handle true client ip (set_host_header)
            if options.get("enableTrueClientIp", False) == True:
                trueClientIpHeader = options.get("trueClientIpHeader", "")
                if trueClientIpHeader:
                    # Unique key for set_host_header
                    if "origin_set_host_header" in seen_behaviors:
                        continue

                    azion_behavior = {
                        "name": "set_host_header",
                        "enabled": True,
                        "description": f"Set host header to {trueClientIpHeader}",
                        "target": { "target": '"' + f'{trueClientIpHeader}: ' + "$${remote_addr}" + '"' }
                    }
                    azion_behaviors.append(azion_behavior)
                    seen_behaviors.add("origin_set_host_header")
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
            }
            azion_behaviors.append(azion_behavior)
            seen_behaviors.add("set_host_header")
            continue

        # Handle special behavior: capture_match_groups
        if mapping["azion_behavior"] == "capture_match_groups":
            required_fields = {
                "captured_array": options.get("variableName"),
                "regex": options.get("regex")
            }
            missing_fields = {k: v for k, v in required_fields.items() if not v}
            if missing_fields:
                logging.warning(f"Behavior '{mapping['azion_behavior']}' is missing required fields: {missing_fields}")
                continue

            azion_behavior = {
                "name": mapping["azion_behavior"],
                "enabled": True,
                "description": behavior.get("description", f"Behavior for {behavior_name}"),
                "target": {
                    "captured_array": f'{replace_variables(options.get("variableValue"))}',
                    "subject": '$${variable}',
                    "regex": f'"(.*)\\\\/{replace_variables(options.get("regex")).replace('/', r'\\/').replace('.', r'\\.')}"'
                },
            }

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
            "description": behavior.get("description", f"Behavior for {behavior_name}")
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

    # Sort behaviors by priority
    azion_behaviors.sort(key=lambda b: b.get("priority", 0))

    return azion_behaviors, depends_on