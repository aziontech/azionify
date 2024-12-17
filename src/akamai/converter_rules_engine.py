import logging
from typing import Dict, List, Any, Set, Tuple
from azion_resources import AzionResource
from akamai.mapping import MAPPING
from akamai.utils import map_forward_host_header, map_origin_type, map_variable
from utils import sanitize_name

def create_rule_engine(azion_resources: AzionResource, rule: Dict[str, Any], main_setting_name: str, index: int) -> List[Dict[str, Any]]:
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
    rule_name = rule.get("name", "Unnamed Rule")

    logging.info(f"Processing rule: {rule_name} with index {index}")

    # Process children rules if present
    children = rule.get("children", [])
    if children:
        logging.info(f"Rule '{rule_name}' has {len(children)} child rules. Delegating to process_children.")
        resources.extend(process_children(azion_resources, children, main_setting_name, index))
        return resources

    # Validate rule before processing
    if not validate_rule_compatibility(rule):
        logging.warning(f"Rule '{rule_name}' is not compatible with Azion format. Skipping.")
        return resources

    # Extract behaviors and criteria
    behaviors = rule.get("behaviors", [])
    criteria = rule.get("criteria", [])

    logging.info(f"Found {len(behaviors)} behaviors and {len(criteria)} criteria for rule: {rule_name}")

    try:
        # Create resource if either behaviors or criteria exist
        if behaviors or criteria:
            # Process conditions
            processed_rule = process_conditional_rule(rule)
            
            # Calculate priority based on position and settings
            priority = process_rule_priority(processed_rule, index)

            # Process behaviors and criteria
            azion_behaviors, depends_on_behaviors = process_behaviors(azion_resources, behaviors)
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
                logging.info(f"Rule engine resource created for rule: {rule_name}")
        else:
            logging.warning(f"No behaviors or criteria found for rule: {rule_name}. Skipping.")
    except ValueError as e:
        logging.error(f"Error processing rule {rule_name}: {str(e)}")

    return resources


def process_children(azion_resources: AzionResource,children: List[Dict[str, Any]], main_setting_name: str, parent_index: int) -> List[Dict[str, Any]]:
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
            # Calculate child priority based on parent index and child position
            child_index = (parent_index * child_priority_multiplier) + index
            resources.extend(create_rule_engine(azion_resources, child, main_setting_name, child_index))
        except ValueError as e:
            logging.error(f"Error processing child rule {child.get('name', 'unnamed')}: {str(e)}")
    return resources

def validate_rule_compatibility(rule: Dict[str, Any]) -> bool:
    """
    Validate if a rule can be properly converted to Azion format.
    
    Parameters:
        rule (dict): The rule to validate.
    
    Returns:
        bool: True if rule is compatible, False otherwise.
    """
    if not rule:
        return False

    required_fields = {"name", "behaviors"}
    if not all(field in rule for field in required_fields):
        logging.warning(f"Missing required fields in rule: {rule.get('name', 'Unknown')}")
        return False
        
    # Verifica se os behaviors são mapeáveis
    behaviors = rule.get("behaviors", [])
    for behavior in behaviors:
        behavior_name = behavior.get("name", "")
        if not (MAPPING.get("advanced_behaviors", {}).get(behavior_name) or 
                MAPPING.get("behaviors", {}).get(behavior_name)):
            logging.warning(f"Unmappable behavior '{behavior_name}' in rule: {rule.get('name')}")
            return False
            
    return True

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

def map_operator(akamai_operator: str) -> str:
    """
    Maps Akamai operators to Azion operators.
    
    Parameters:
        akamai_operator (str): Akamai operator
        
    Returns:
        str: Azion operator
    """
    operator_map = {
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
        "DOES_NOT_EXIST": "does_not_exist"
    }
    return operator_map.get(akamai_operator, "matches")  # default to matches if unknown

def process_criteria(criteria: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Processes and maps Akamai criteria to Azion-compatible criteria.

    Parameters:
        criteria (List[Dict[str, Any]]): List of Akamai criteria.

    Returns:
        List[Dict[str, Any]]: List of Azion criteria grouped by phase.
    """
    if not criteria:
        return []

    # Map Akamai's criteriaMustSatisfy to Azion's conditional
    criteria_must_satisfy = criteria[0].get("criteriaMustSatisfy", "all")
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
            akamai_operator = options.get("matchOperator", "MATCHES")
            azion_operator = map_operator(akamai_operator)

            # Handle input values
            values = options.get("values", [])
            if isinstance(values, str):
                values = [values]

            # Handle single or multiple values based on the operator
            if azion_operator in {"exists", "does_not_exist"}:
                input_value = None
            else:
                # Handle single vs multiple values
                if len(values) > 1:
                    if name == "fileExtension":
                        input_value = r".*\\.(%s)$" % "|".join(values)
                    else:
                        input_value = "|".join(values)
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
    azion_criteria = []
    if request_entries:
        azion_criteria.append({"entries": request_entries})
    if response_entries:
        azion_criteria.append({"entries": response_entries})

    return azion_criteria

def process_behaviors(azion_resources: AzionResource,behaviors: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Set[str]]:
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

    for behavior in behaviors:
        behavior_name = behavior.get("name")
        if not behavior_name or behavior_name not in MAPPING.get("behaviors", {}):
            logging.warning(f"Unmapped behavior: {behavior_name}")
            logging.debug(f"Behavior options: {behavior.get('options', {})}")
            continue

        mapping = MAPPING["behaviors"][behavior_name]
        options = behavior.get("options", {})

        # Skip behaviors that are explicitly disabled
        if "enabled" in options and options["enabled"] is False:
            logging.debug(f"Behavior '{behavior_name}' is explicitly disabled. Skipping.")
            continue

        # Handle special behavior: set_cache_policy
        if mapping["azion_behavior"] == "set_cache_policy":
            # Unique key for set_cache_policy
            if "set_cache_policy" in seen_behaviors:
                continue

            # Handle cache settings dependencies
            cache_setttings = azion_resources.query_azion_resource_by_type('azion_edge_application_cache_setting')
            if cache_setttings:
                cache_settings_name = cache_setttings.get("name")
                cache_settings_ref = f'azion_edge_application_cache_setting.{cache_settings_name}'
                depends_on.add(cache_settings_ref)

                azion_behavior = {
                    "name": "set_cache_policy",
                    "enabled": True,
                    "target": {"target": f"{cache_settings_ref}.id"},
                    "description": f"Set cache policy to {options.get('name', '')}"
                }   
                azion_behaviors.append(azion_behavior)
                seen_behaviors.add("set_cache_policy")
            continue

        # Handle special behavior: set_host_header
        if mapping["azion_behavior"] == "set_host_header":
            # Unique key for set_cache_policy
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
                    "captured_array": f'{map_variable(options.get("variableValue"), context="captured_array")}',
                    "subject": '$${variable}',
                    "regex": f'{options.get("regex")}'
                },
            }

            # Create a unique key to track this behavior
            unique_key = (azion_behavior["name"], tuple(sorted(azion_behavior.get("target", {}).items())))
            if unique_key in seen_behaviors:
                logging.debug(f"Duplicate behavior detected: {unique_key}. Skipping.")
                continue

            azion_behaviors.append(azion_behavior)
            seen_behaviors.add(unique_key)
            continue


        # Skip if we've already processed this behavior type
        if mapping["azion_behavior"] in seen_behaviors:
            logging.debug(f"Behavior '{mapping['azion_behavior']}' already processed. Skipping.")
            continue

        azion_behavior = {
            "name": mapping["azion_behavior"],
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
                        logging.error(f"Error processing target for key '{target_key}' in behavior '{behavior_name}': {e}")
            elif isinstance(mapping["target"], str):
                try:
                    value = options.get(mapping["target"])
                    if value is not None:
                        target = value
                except ValueError as e:
                    logging.error(f"Error accessing target for behavior '{behavior_name}': {e}")

            # Special handling for origin
            if azion_behavior["name"] == "set_origin":
                target["origin_type"] = map_origin_type(options.get("originType", "CUSTOMER"))

            if target:  # Only add target if we have values
                azion_behavior["target"] = target

        azion_behaviors.append(azion_behavior)
        seen_behaviors.add(mapping["azion_behavior"])

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