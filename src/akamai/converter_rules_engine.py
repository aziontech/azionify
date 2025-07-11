import logging
import re
import copy
from typing import Dict, List, Any, Set, Tuple, Optional
from azion_resources import AzionResource
from akamai.mapping import MAPPING
from akamai.utils import (
    map_forward_host_header,
    map_origin_type,
    replace_variables,
    map_operator,
    behavior_key,
    AKAMAI_TO_AZION_MAP
)
from akamai.converter_edge_function_instance import create_edge_function_instance
from utils import (
    sanitize_name, 
    find_function, 
    compact_and_sanitize, 
    transform_expression,
)

DEFAULT_CRITERIA = {
    "name": "default",
    "variable": "$${uri}",
    "operator": "starts_with",
    "conditional": "if",
    "input_value": "/"
}
CONDITIONAL_MAP = {
    "all": "and",
    "any": "or",
    "one": "if"
}
BEHAVIOR_CACHE_PHASE = ["NO_STORE", "NO_CACHE"]


# Create order factory
def create_order_factory(multiplier: int=10) -> int:
    current = 2

    def create_order() -> int:
        nonlocal current
        value = current
        current += 1
        return (value * multiplier)
    
    return create_order
create_request_rule_order = create_order_factory()
create_response_rule_order = create_order_factory()
create_variable_rule_order = create_order_factory(multiplier=1)

def create_behavior_from_variables(variables: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    azion_behaviors = []
    for var in variables:
        varname = var.get("name")
        if not varname:
            continue

        value = var.get("value")
        if not value or value == "":
            continue

        if "PMUSER_" in varname:
            varname = varname.removeprefix('PMUSER_')
        varname = varname[:10]
        varname = sanitize_name(varname)

        azion_behavior = {
            "name": "add_request_header",
            "enabled": True,
            "target": {
                "target": f'\"{varname}: {value}\"'
            },
            "phase": "request"
        }
        azion_behaviors.append(azion_behavior)
    return azion_behaviors

def create_rule_engine(
        azion_resources: AzionResource,
        rule: Dict[str, Any],
        context: Dict[str, Any],
        name: str = None,
    ) -> List[Dict[str, Any]]:
    """
    Create a rule engine resource from Akamai rule data.

    Parameters:
        azion_resources (AzionResource): Azion resource container
        rule (Dict[str, Any]): Akamai rule data
        context (Dict[str, Any]): Context variables
        name (str): Rule name

    Returns:
        List[Dict[str, Any]]: Azion rule engine resource
    """
    resources = []
    index = context.get("rule_index", 0)
    rule_name = name if name else rule.get("name", f"Unnamed Rule_{index}")
    main_setting_name = context.get("main_setting_name", "unnamed")
    if rule_name != "default":
        rule_name = f'{compact_and_sanitize(rule_name)}_{index}'

    logging.info(f"[rules_engine] Processing rule: '{rule_name}' with index {index}")

    # Extract behaviors and criteria
    behaviors = rule.get("behaviors", [])
    criteria = context.get("criteria", [])
    rule_condition = rule.get("criteriaMustSatisfy", "one")

    logging.info(
        f"[rules_engine] Found {len(behaviors)} behaviors and {len(criteria)} criteria for rule: '{rule_name}'"
    )

    try:
        # Create resource if either behaviors or criteria exist
        if behaviors or criteria:
            # Process conditions
            processed_rule = process_conditional_rule(rule)
            context["rule"] = processed_rule
            context["resources"] = resources

            # Process behaviors and criteria
            azion_behaviors, depends_on_behaviors = process_behaviors(azion_resources, behaviors, context, rule_name)
            behaviors_names = [behavior.get("name") for behavior in behaviors]
            azion_criteria = process_criteria(rule, criteria, behaviors_names, rule_condition)

            # Handling depends_on
            depends_on = [f"azion_edge_application_main_setting.{main_setting_name}"]
            depends_on.extend(list(depends_on_behaviors))

            # Handling default variables
            if rule_name == "default":
                variables_behaviors = create_behavior_from_variables(rule.get("variables", []))
                slices = [variables_behaviors[i:i+10] for i in range(0, len(variables_behaviors), 10)]
                for behaviors in slices:
                    rule = create_variable_rule(
                        'default_variables',
                        behaviors,
                        main_setting_name,
                        azion_criteria.get("request_default", []),
                        depends_on)
                    resources.append(rule)

            # Handling behaviors by phase
            request_behaviors = []
            response_behaviors = []
            for behavior in azion_behaviors:
                if behavior.get('phase', 'both') == 'both':
                    request_behaviors.append(behavior)
                    response_behaviors.append(behavior)
                elif behavior.get('phase', 'request') == 'request':
                    request_behaviors.append(behavior)
                elif behavior.get('phase', 'request') == 'response':
                    response_behaviors.append(behavior)

            # Create request phase rule
            if len(request_behaviors) > 0:
                rules = assemble_request_rule(processed_rule, 
                                                rule_name, 
                                                index,
                                                main_setting_name, 
                                                azion_criteria, 
                                                request_behaviors, 
                                                depends_on)
                if rules:
                    for rule in rules:
                        resources.append(rule)
                        logging.info(f"[rules_engine] Rule engine resource (request) created for rule: '{rule.get('name')}'")

            # Create response phase rule
            if len(response_behaviors) > 0:
                resource = assemble_response_rule(processed_rule, 
                                                rule_name, 
                                                index,
                                                main_setting_name, 
                                                azion_criteria, 
                                                response_behaviors, 
                                                depends_on)
                if resource:
                    resources.append(resource)
                    logging.info(f"[rules_engine] Rule engine resource (response) created for rule: '{rule_name}'")

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

def create_variable_rule(
        name: str,
        behaviors: List[Dict[str, Any]],
        main_setting_name: str,
        criteria: List[Dict[str, Any]],
        depends_on: List[str]
    ) -> Dict[str, Any]:
    """
    Create a variable rule engine resource from Akamai variable data.

    Parameters:
        behaviors (List[Dict[str, Any]]): Akamai variable data
        main_setting_name (str): Name of the main setting
        depends_on (List[str]): List of dependencies for the rule

    Returns:
        List[Dict[str, Any]]: List of variable rule engine resources
    """
    order = create_variable_rule_order()
    resource = {
        "type": "azion_edge_application_rule_engine",
        "name": f'{compact_and_sanitize(name)}_{order}',
        "order": order,
        "phase": "request",
        "attributes": {
            "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.edge_application.application_id",
            "results": {
                "name": f'{compact_and_sanitize(name)}_{order}',
                "description": "",
                "phase": "request",
                "behaviors": behaviors,
                "criteria": criteria,
                "order": order
            },
            "depends_on": depends_on
        }
    }
    return resource

def assemble_request_rule(
        rule: Dict[str, Any],
        rule_name: str,
        index: int,
        main_setting_name: str,
        azion_criteria: Dict[str, Any],
        request_behaviors: List[Dict[str, Any]],
        depends_on: List[str]
    ) -> List[Dict[str, Any]]:
    """
    Create a list of rule engine resources from Akamai rule data.
    Rules with multiple 'run_function' or 'rewrite_request' behaviors are split into separate rules.

    Parameters:
        rule (Dict[str, Any]): Akamai rule data.
        rule_name (str): Name of the rule.
        main_setting_name (str): Name of the main setting.
        azion_criteria (Dict[str, Any]): Criteria to be used in the rule.
        request_behaviors (List[Dict[str, Any]]): List of behaviors to be applied in the rule.
        depends_on (List[str]): List of dependencies for the rule.

    Returns:
        List[Dict[str, Any]]: List of rule engine resources.
    """
    phase = "request"
    rule_description = rule.get("comments", "").replace("\n", " ").replace("\r", " ").replace("\"", "'")
    
    result_rules = []
    
    # Group behaviors by type
    special_behaviors = []  # 'run_function' or 'rewrite_request' behaviors
    standard_behaviors = []  # Other behaviors
    
    for behavior in request_behaviors:
        if behavior.get("name") in ["run_function", "rewrite_request"]:
            special_behaviors.append(behavior)
        else:
            standard_behaviors.append(behavior)

    # if only one space behavior found, so there's no need to create a separate rule for it
    if len(special_behaviors) == 1:
        standard_behaviors.append(special_behaviors[0])
        special_behaviors = []

    if len(standard_behaviors) > 0:
        # Check if no criteria found
        criteria = azion_criteria.get("request", None)
        if not criteria:
            if rule_name == 'default':
                criteria = azion_criteria.get("request_default", None)
                logging.warning(f"[rules_engine][assemble_request_rule] Using default criteria for rule: '{rule_name}'.")
            else:
                logging.warning(f"[rules_engine][assemble_request_rule] No criteria found for rule: '{rule_name}'.")
                return []

        if rule_name == 'default':
            phase = "default"
            order = 1
        else:
            order = create_request_rule_order()

        resource = {
            "type": "azion_edge_application_rule_engine",
            "name": rule_name, 
            "order": order,
            "phase": phase,
            "attributes": {
                "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.edge_application.application_id",
                "results": {
                    "name": "Default Rule" if phase == "default" else rule_name,
                    "description": rule_description,
                    "phase": phase,
                    "behaviors": standard_behaviors,
                    "criteria": criteria,
                    "order": order
                },
                "depends_on": depends_on
            }
        }
        result_rules.append(resource)

    if  len(special_behaviors) > 0:
        # Check if no criteria found
        criteria = azion_criteria.get("request", None)
        if not criteria:
            logging.warning(f"[rules_engine][assemble_request_rule] No criteria found for rule: '{rule_name}'.")
        
        # Create a rule for each special behavior, combined with all standard behaviors
        for idx, special_behavior in enumerate(special_behaviors):
            order = create_request_rule_order()
            suffix = f"_{order}_sp{idx+1}"
            unique_rule_name = rule_name + suffix

            if not criteria:
                criteria = azion_criteria.get("request_default", None)
                logging.warning(f"[rules_engine][assemble_request_rule] Using default criteria for rule: '{rule_name}'.")
            
            resource = {
                "type": "azion_edge_application_rule_engine",
                "name": unique_rule_name, 
                "order": order,
                "phase": "request",
                "attributes": {
                    "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.edge_application.application_id",
                    "results": {
                        "name": unique_rule_name,
                        "description": f"{rule_description} (Rule '{rule_name}' split {idx+1}/{len(special_behaviors)})",
                        "phase": "request",
                        "behaviors": [special_behavior],
                        "criteria": criteria,
                        "order": order
                    },
                    "depends_on": depends_on
                }
            }
            result_rules.append(resource)
    
    return result_rules

def assemble_response_rule(
        rule: Dict[str, Any],
        rule_name: str,
        index: int,
        main_setting_name: str,
        azion_criteria: Dict[str, Any],
        behaviors: List[Dict[str, Any]],
        depends_on: List[str]
    ) -> Optional[Dict[str, Any]]:
    """
    Create a rule engine resource from Akamai rule data.

    Parameters:
        rule (Dict[str, Any]): Akamai rule data.
        rule_name (str): Name of the rule.
        main_setting_name (str): Name of the main setting.
        azion_criteria (Dict[str, Any]): Criteria to be used in the rule.
        behaviors (List[Dict[str, Any]]): List of behaviors to be applied in the rule.
        depends_on (List[str]): List of dependencies for the rule.

    Returns:
        Dict[str, Any]: Rule engine resource.
    """
    
    behavior_names = "_".join(sorted(set(b.get("name", "") for b in behaviors)))
    behavior_names = compact_and_sanitize(behavior_names, 30)
    name = compact_and_sanitize(rule_name, 60)
    unique_rule_name = f"{name}_{behavior_names}_{index}"

    # Find criteria for the behavior
    criterias = azion_criteria.get("response", {}).get("entries")
    selected_criteria = None
    if criterias:
        if len(criterias) == 1:
            selected_criteria = azion_criteria.get("response")
        else:
            selection = []
            for criteria in criterias:
                for behavior in behaviors:
                    if criteria.get("name", "") == behavior.get('name') or \
                        criteria.get("phase", "both") != "request":
                        selection.append(criteria)
                        break
            selected_criteria = {"entries": selection}
    else:
        #selected_criteria = azion_criteria.get("response_default")
        logging.warning(f"[rules_engine][assemble_response_rule] No criteria found for rule: '{rule_name}'. Skipping.")
        return None

    rule_description = rule.get("comments", "").replace("\n", " ").replace("\r", " ").replace("\"", "'")
    order = create_response_rule_order()
    resource = {
        "type": "azion_edge_application_rule_engine",
        "name": unique_rule_name,
        "order": order,
        "phase": "response",
        "attributes": {
            "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.edge_application.application_id",
            "results": {
                "name": unique_rule_name,
                "description": rule_description,
                "phase": "response",
                "behaviors": behaviors,
                "order": order
            },
            "depends_on": depends_on
        }
    }

    # Only add criteria if we have entries
    if len(selected_criteria) > 0:
        resource["attributes"]["results"]["criteria"] = selected_criteria
    return resource

def process_conditional_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process rules with conditions and create Azion-compatible conditions.
    
    Parameters:
        rule (Dict[str, Any]): The rule to process.
    
    Returns:
        Dict[str, Any]: Processed rule with Azion-compatible conditions.
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
            elif condition_name == "requestHeader":
                header_name = condition["options"]["headerName"]
                mapping["azion_condition"] = f"$${{http_{sanitize_name(header_name)}}}"
            elif condition_name == "cloudletsOrigin":
                azion_conditions.append({
                    "conditional": mapping["azion_condition"],
                    "operator": mapping["azion_operator"],
                    "input_value": condition.get("options", {}).get("originId", "")
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
    """
    Process default criteria for when no criteria is defined.

    Parameters:
        behaviors_names (List[str]): List of behavior names.

    Returns:
        Dict[str, Any]: Processed criteria.
    """

    azion_criteria = {}
    request_entries = []
    response_entries = []

    # Default criteria for when no criteria is defined
    for behavior_name in behaviors_names:
        mapping = MAPPING.get("criteria", {}).get(behavior_name)
        
        if mapping:
            entry = {
                "name": mapping.get("name", behavior_name),
                "variable": mapping.get("azion_condition"),
                "operator": mapping.get("azion_operator"),
                "conditional": mapping.get("conditional"),
                "phase": mapping.get("phase", "request"),
                "akamai_behavior": mapping.get("akamai_behavior", ""),
                "parent": ""
            }
            if mapping.get("azion_operator"):
                entry["input_value"] = mapping.get("input_value")
            # Append to the correct phase
            if mapping.get("phase") == "response":
                response_entries.append(entry)
            else:
                request_entries.append(entry)

    azion_criteria["request_default"] = {"entries":[DEFAULT_CRITERIA]}
    azion_criteria["response_default"] = {"entries":[DEFAULT_CRITERIA]}
    if len(request_entries) > 0:
        azion_criteria["request"] = {"entries": request_entries}
        logging.info("No criteria found for request phase of the rule, using default criterias based on the behaviors")
    if len(response_entries) > 0:
        azion_criteria["response"] = {"entries": response_entries}
        logging.info("No criteria found for response phase of the rule, using default criterias based on the behaviors")   
    return azion_criteria

def process_criteria(
        rule: Dict[str, Any],
        criteria: List[Dict[str, Any]],
        behaviors_names: List[str],
        rule_condition: str,
    ) -> List[Dict[str, Any]]:
    """
    Processes and maps Akamai criteria to Azion-compatible criteria.

    Parameters:
        criteria (List[Dict[str, Any]]): List of Akamai criteria.
        behaviors_names (List[str]): List of behavior names.
        rule_condition (str): Condition to group criteria

    Returns:
        List[Dict[str, Any]]: List of Azion criteria grouped by phase.
    """
    azion_criteria = {}
    request_entries = []
    response_entries = []
    criteria_has_condition = rule.get("criteriaMustSatisfy", "one")

    logging.info(f'[rules_engine][process_criteria] Processing criteria for rule: {rule.get("name")}')
    if not criteria:
        azion_criteria = process_criteria_default(behaviors_names)
        return azion_criteria

    for index, criterion in enumerate(criteria):
        name = criterion.get("name")
        options = criterion.get("options", {})
        if not name:
            logging.warning(f"[rules_engine][process_criteria] Criterion {criterion} at index {index} is missing a name. Skipping.")
            continue

        mapping = MAPPING.get("criteria", {}).get(name)
        if not mapping:
            logging.warning(f"[rules_engine][process_criteria] No mapping found for criterion: {name}. Skipping.")
            continue
        # Map Akamai's criteriaMustSatisfy to Azion's conditional
        group_conditional = CONDITIONAL_MAP.get(criteria_has_condition, "one") if index == 0 else CONDITIONAL_MAP.get(rule_condition, "and") 

        try:
            # Map operator
            akamai_operator = options.get("matchOperator", "EQUALS") 
            if callable(mapping.get("azion_operator")):
                azion_operator = mapping["azion_operator"](options)
            else:
                azion_operator = mapping.get("azion_operator")
            if azion_operator is None:
                azion_operator = map_operator(akamai_operator)

            # Handle input values
            if 'originId' in options:
                values = [options.get("originId", "")]
            elif 'values' in options:
                values = options.get("values", [])
            elif 'variableValues' in options:
                values = options.get("variableValues", [])
            elif 'variableExpression' in options:
                values = options.get("variableExpression", ['*'])
                values = [values]
            else:
                values = [options.get("value", "")]

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

            # Handle variable
            if callable(mapping.get("azion_condition")):
                azion_condition = mapping["azion_condition"](options)
            else:
                azion_condition = mapping.get("azion_condition")

            # Build the entry
            entry = {
                "variable": azion_condition,
                "operator": azion_operator,
                "conditional": group_conditional,
                "akamai_behavior": mapping.get("akamai_behavior",""),
                "parent": criterion.get('parent', ""),
                "parent_rule_condition": criterion.get('parent_rule_condition', "")
            }
            if input_value is not None:
                entry["input_value"] = input_value.replace("\r", "")

            # Append to the correct phase
            if mapping.get("phase") == "response":
                response_entries.append(entry)
            elif mapping.get("phase") == "request":
                request_entries.append(entry)
            else:
                response_entries.append(entry)
                request_entries.append(entry)

        except ValueError as e:
            logging.error(f"[rules_engine][process_criteria] Error processing criterion {name}: {str(e)}")

    # Assemble criteria groups
    if len(request_entries) > 0:
        for index in range(len(request_entries)):
            request_entries[index] = copy.deepcopy(request_entries[index])
            if index == 0:
                request_entries[index]["conditional"] = "if"
            else:
                if criteria_has_condition == "all":
                    request_entries[index]["conditional"] = "and"
                else:
                    request_entries[index]["conditional"] = "or"

    if len(response_entries) > 0:
        for index in range(len(response_entries)):
            response_entries[index] = copy.deepcopy(response_entries[index])
            if index == 0:
                response_entries[index]["conditional"] = "if"
            else:
                if criteria_has_condition == "all":
                    response_entries[index]["conditional"] = "and"
                else:
                    response_entries[index]["conditional"] = "or"

    azion_criteria = {
        'request': {'entries': request_entries},
        'response': {'entries': response_entries}
    }

    if len(request_entries) == 0 and len(response_entries) == 0:
        azion_criteria = process_criteria_default(behaviors_names)

    logging.info(f'[rules_engine][process_criteria] Processed criteria for rule: {rule.get("name")}, request {len(request_entries)}, response {len(response_entries)}')
    return azion_criteria

def behavior_cache_setting(
        context: Dict[str, Any],
        azion_resources: AzionResource,
        options: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], str]:
    """
    Handles cache settings dependencies for a behavior.

    Parameters:
        context (Dict[str, Any]): The context dictionary containing rule information.
        azion_resources (AzionResource): The Azion resource container.
        options (Dict[str, Any]): The options dictionary containing cache settings information.

    Returns:
        Tuple[Dict[str, Any], str]: A tuple containing the Azion behavior and cache settings reference.
    """

    azion_behavior = None
    cache_settings_ref = None

    parent_rule_name = context.get("parent_rule_name")
    rule_name = context.get("rule_name")

    behavior = options.get("behavior", "").upper()
    if behavior in BEHAVIOR_CACHE_PHASE:
        azion_behavior = {
            "name": "bypass_cache_phase",
            "enabled": True,
            "target": {},
            "phase": "request"
        }
        return azion_behavior, None
    else: 
        # Handle cache settings dependencies
        cache_setttings = context.get("cache_setting")
        if cache_setttings is None:
            _, cache_setttings = azion_resources.query_azion_resource_by_type(
                'azion_edge_application_cache_setting', sanitize_name(parent_rule_name), match="prefix")
            if cache_setttings is None:
                _, cache_setttings = azion_resources.query_azion_resource_by_type(
                    'azion_edge_application_cache_setting', sanitize_name(rule_name), match="prefix")

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

def behavior_set_origin(
        context: Dict[str, Any],
        azion_resources: AzionResource,
        options: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], str]:
    """
    Handles origin settings dependencies for a behavior.

    Parameters:
        context (Dict[str, Any]): The context dictionary containing rule information.
        azion_resources (AzionResource): The Azion resource container.
        options (Dict[str, Any]): The options dictionary containing origin settings information.

    Returns:
        Tuple[Dict[str, Any], str]: A tuple containing the Azion behavior and origin settings reference.
    """

    azion_behavior = None
    origin_settings_ref = None

    rule_name = context.get("rule_name")
    parent_rule_name = context.get("parent_rule_name", "unamed")

    # Handle origin settings dependencies
    origin_settings = context.get("origin")
    if origin_settings is None:
        _, origin_settings = azion_resources.query_azion_resource_by_type(
        "azion_edge_application_origin",
        sanitize_name(parent_rule_name), match="prefix")
        if origin_settings is None:
            _, origin_settings = azion_resources.query_azion_resource_by_type(
                "azion_edge_application_origin",
                sanitize_name(rule_name), match="prefix")
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
            "phase": "request",
            "akamai_behavior": "setOrigin"
        }

    return azion_behavior, origin_settings_ref

def behavior_capture_match_groups(
        options: Dict[str, Any],
        mapping: Dict[str, Any],
        behavior: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
    """
    Handles capture match groups dependencies for a behavior.

    Parameters:
        options (Dict[str, Any]): The options dictionary containing capture match groups information.
        mapping (Dict[str, Any]): The mapping dictionary containing the behavior information.
        behavior (Dict[str, Any]): The behavior dictionary containing the behavior information.

    Returns:
        List[Dict[str, Any]]: A list of Azion behaviors.
    """
    azion_behaviors = []
    value = None

    if options.get("globalSubstitution", False):
        logging.warning("'setVariable' with 'globalSubstitution = TRUE' is not supported for capture match groups")
        return azion_behaviors

    required_fields = {
        "captured_array": options.get("variableName")
    }
    missing_fields = {k: v for k, v in required_fields.items() if not v}
    if missing_fields:
        logging.warning(f"Behavior '{mapping['azion_behavior']}' is missing required fields: {missing_fields}")
        return azion_behaviors

    varname = options.get("variableName",f"var{mapping['azion_behavior']}")
    if "PMUSER_" in varname:
        varname = varname.removeprefix('PMUSER_')
    varname = varname[:10]

    # Set variable
    if options.get('regex') is None:
        if options.get('extractLocation','').upper() in ['CLIENT_REQUEST_HEADER', 'QUERY_STRING', 'RESPONSE_HEADER']:
            if options.get('extractLocation','').upper() == 'CLIENT_REQUEST_HEADER':
                value = sanitize_name(options.get("headerName", "$${http_header}"))
            elif options.get('extractLocation','').upper() == 'QUERY_STRING':
                value = "$${args}"
            elif options.get('extractLocation','').upper() == 'RESPONSE_HEADER':
                value = "$${sent_http_header}"
            else:
                value = "$${uri}"          
            
            # Capture header content
            azion_behavior = {
                "name": mapping["azion_behavior"],
                "enabled": True,
                "phase": "request",
                "description": behavior.get(
                    "description", 
                    "Capture content from header: " + varname
                ),
                "target": {
                    "captured_array": f'"{varname}"',
                    "subject": f'"$${{http_{value}}}"',
                    "regex": "\"(.*)\"",
                }
            }
            azion_behaviors.append(azion_behavior)
            value = f'%%{{{varname}}}'

        # Handle variable name
        if value is None:
            value = options.get("variableValue", varname)
        captured_array = sanitize_name(varname)

        azion_behavior = {
            "name": "add_request_header",
            "enabled": True,
            "target": {
                "target": f'\"{captured_array}: {value}\"'
            },
            "phase": "request"
        }
        azion_behaviors.append(azion_behavior)

        azion_behaviors.append({
            "name": "setvar",
            "var": captured_array, 
            "value": f'$${{http_{captured_array}}}',
            "target": value
        })
        AKAMAI_TO_AZION_MAP[varname] = value
        return azion_behaviors

    regex_value = replace_variables(options.get('regex')).replace('/', r'\/').replace('.', r'\\.').replace(r'\d', r'\\d')
    captured_array = varname[:10]
    if "PMUSER_" in options.get("variableValue", ""):
        subject = "$${uri}"
    else:
        subject = replace_variables(options.get("variableValue","$${uri}"))
    azion_behavior = {
        "name": mapping["azion_behavior"],
        "enabled": True,
        "phase": "request",
        "description": behavior.get(
            "description", 
            "Behavior capture_match_groups, variableName: " + options.get("variableName", "")
        ),
        "target": {
            "captured_array": f'"{captured_array}"',
            "subject": f'{subject}',
            "regex": f"\"{regex_value}\"",
        }
    }
    azion_behaviors.append(azion_behavior)

    if options.get('transform','').upper() == 'SUBSTITUTE':
        target = transform_expression(options.get('replacement',f'{captured_array}{1}'), captured_array)
        azion_behaviors.append({
            "name": "setvar",
            "var": captured_array, 
            "value": f'$${{http_{captured_array}}}',
            "target": target
        })
        AKAMAI_TO_AZION_MAP[captured_array] = target
    elif options.get('transform','').upper() in ['NONE','TRIM']:
        azion_behaviors.append({
            "name": "setvar",
            "var": captured_array, 
            "value": f'$${{http_{captured_array}}}',
            "target": options.get("variableValue", "")
        })
        AKAMAI_TO_AZION_MAP[captured_array] = options.get("variableValue", "")

    return azion_behaviors

def behavior_rewrite_request(options, name):
    behaviors = []
    option_behavior = options.get("behavior")

    if option_behavior == "REWRITE":
        azion_behavior = {
            "name": "rewrite_request",
            "enabled": True,
            "target": {
                "target": f"\"{replace_variables(options.get('targetUrl','$${uri}')).strip()}\""
            },
            "phase": "request",
            "akamai_behavior": "rewriteUrl_REWRITE"
        }
        behaviors.append(azion_behavior)
    elif option_behavior == "REPLACE":
        regex_value = replace_variables(options.get('match')).replace('/', r'\\/').replace('.', r'\\.')
        captured_array = sanitize_name(name).upper()[:10]
        captured_array = re.sub(r"\d+", "", captured_array) # Remove all numeric characters
        subject = '$${request_uri}'
        behavior_match_group = {
            "name": "capture_match_groups",
            "enabled": True,
            "target": {
                "captured_array": f"\"{captured_array}\"",
                "subject": f'{subject}',
                "regex": f"\"{regex_value}(.*)\"",
            },
            "phase": "request",
            "akamai_behavior": "rewriteUrl_REPLACE"
        }
        behaviors.append(behavior_match_group)
        behavior_rewrite = {
            "name": "rewrite_request",
            "enabled": True,
            "target": {
                "target": f"\"{replace_variables(options.get('targetPath','$${request_uri}')).strip()}%%{{{captured_array}[1]}}\""
            },
            "phase": "request",
            "akamai_behavior": "rewriteUrl_REPLACE"
        }
        behaviors.append(behavior_rewrite)
    elif option_behavior == "PREPEND":
        newurl = options.get("targetPathPrepend","") + "$${request_uri}"
        azion_behavior = {
            "name": "rewrite_request",
            "enabled": True,
            "target": {
                "target": f"\"{newurl}\""
            },
            "phase": "request",
            "akamai_behavior": "rewriteUrl_PREPEND"
        }
        behaviors.append(azion_behavior)
    elif option_behavior == "REMOVE":
        match_value = replace_variables(options.get('match', ''))
        escaped_match = match_value.replace('/', r'\/').replace('.', r'\.')
        regex_value = f"^(.*){escaped_match}(.*)$"
        captured_array = sanitize_name(name).upper()[:10]
        captured_array = re.sub(r"\d+", "", captured_array) # Remove all numeric characters
        subject = '$${request_uri}'
        behavior_match_group = {
            "name": "capture_match_groups",
            "enabled": True,
            "target": {
                "captured_array": f'"{captured_array}"',
                "subject": f'{subject}',
                "regex": f"\"{regex_value}\"",
            },
            "phase": "request",
            "akamai_behavior": "rewriteUrl_REPLACE"
        }
        behaviors.append(behavior_match_group)
        azion_behavior = {
            "name": "rewrite_request",
            "enabled": True,
            "target": {
                "target": f"\"%%{{{captured_array}[1]}}%%{{{captured_array}[2]}}\""
            },
            "phase": "request",
            "akamai_behavior": "rewriteUrl_PREPEND"
        }
        behaviors.append(azion_behavior)
    return behaviors

def process_forward_rewrite(context,
                           name, 
                           index,
                           main_setting_name,
                           depends_on) -> List[Dict[str, Any]]:
    """
    Add rule engine forward rewrite behavior
    Args:
        context (dict): The context dictionary containing the rule and resources.
        name (str): The name of the rule.
        main_setting_name (str): The name of the main setting.
        depends_on (set): A set of dependencies.
    Returns:
        resource (dict): The resource dictionary containing the rule and resources.
    """
    forwardRewrite_criteria = {
        "request": {
            "entries": [
                {
                    "variable": "$${http_x_az_forward_rewrite_uri}",
                    "operator": "exists",
                    "conditional": "if",
                    "input_value": "*",
                    "akamai_behavior": "forwardRewrite",
                    "parent": ""
                }
            ]
        }
    }
    forwardRewrite_behaviors = [
        {
            "name": "rewrite_request",
            "enabled": True,
            "description": f"Behavior for {name}",
            "phase": "request",
            "target": {
                "target": '"/$${http_x_az_forward_rewrite_uri}"'
            }
        }
    ]
    resource = assemble_request_rule(context.get("rule"), 
                                    name, 
                                    index + 1,
                                    main_setting_name, 
                                    forwardRewrite_criteria, 
                                    forwardRewrite_behaviors, 
                                    depends_on)

    if len(resource) > 0:
        if resource[0]['order'] < 100:
            resource[0]['order'] = 100
    return resource

def process_behaviors(
        azion_resources: AzionResource,
        behaviors: List[Dict[str, Any]],
        context: Dict[str, Any],
        rule_name: str,
        parent_rule_name: str = None
    ) -> Tuple[List[Dict[str, Any]], Set[str]]:
    """
    Process and map Akamai behaviors to Azion-compatible behaviors.

    Parameters:
        azion_resources (AzionResource): The Azion resource container.
        behaviors (List[Dict[str, Any]]): List of Akamai behaviors.
        context (Dict[str, Any]): The context dictionary containing rule information.
        rule_name (str): The name of the rule.
        parent_rule_name (str): The name of the parent rule.

    Returns:
        Tuple[List[Dict[str, Any]], Set[str]]: A tuple containing a list of Azion-compatible behaviors and a set of dependencies.
    """
    if not behaviors:
        return [], set()

    azion_behaviors = []
    seen_behaviors = set()  # Track unique behaviors
    cache_policy_options = {}  # Collect all cache policy related options
    depends_on = set()
    parent_rule_name = context.get("parent_rule_name", rule_name)
    rule_index = context.get("rule_index", 0)
    context['envvar'] = None

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
        options['context'] = context

        # Handle behavior name
        if callable(mapping.get("azion_behavior")):
            try:
                behavior_name = mapping["azion_behavior"](options)
            except ValueError as e:
                logging.error(f"[rules_engine][process_behaviors] Error processing azion_behavior in behavior '{ak_behavior_name}': {e}")
        else:
            behavior_name = mapping["azion_behavior"]

        if behavior_name is None:
            logging.debug(f"[rules_engine][process_behaviors] Behavior '{ak_behavior_name}' has no azion_behavior. Skipping.")
            continue

        logging.info(f"[rules_engine][process_behaviors] Mapping from '{ak_behavior_name}' to '{behavior_name}'")

        # Skip behaviors that are explicitly disabled
        if "enabled" in options and options["enabled"] is False:
            logging.debug(f"[rules_engine][process_behaviors] Behavior '{behavior_name}' is explicitly disabled. Skipping.")
            continue

        # Handle special behavior: set_cache_policy
        if mapping["azion_behavior"] == "set_cache_policy":
            azion_behavior, cache_settings_ref = behavior_cache_setting(context, azion_resources, options)
            unique_key = behavior_key(azion_behavior)
            # Unique key for set_cache_policy
            if unique_key in seen_behaviors:
                logging.debug(f"[rules_engine][process_behaviors] already processed behavior {behavior_name}, key {unique_key}. Skipping.")
                continue
    
            if azion_behavior:
                if cache_settings_ref is not None:
                    depends_on.add(cache_settings_ref)
                azion_behaviors.append(azion_behavior)
                seen_behaviors.add(unique_key)
            else:
                logging.debug(f"[rules_engine][process_behaviors] Cache settings not found for rule '{rule_name}'. Skipping.")
            continue

        # Handle special behavior: set_origin
        if mapping["azion_behavior"] == "set_origin":
            azion_behavior, origin_settings_ref = behavior_set_origin(context, azion_resources, options)
            unique_key = behavior_key(azion_behavior)
            # Unique key for set_origin
            if unique_key in seen_behaviors:
                logging.debug(f"[rules_engine][process_behaviors] already processed behavior {behavior_name}, key {unique_key}. Skipping.")
                continue

            if azion_behavior:
                azion_behaviors.append(azion_behavior)
                seen_behaviors.add(unique_key)
                depends_on.add(origin_settings_ref)
            else:
                logging.debug(f"[rules_engine][process_behaviors] Origin settings not found for rule '{rule_name}'. Skipping.")
                continue

            # Handle compression
            if options.get("compress", True):
                azion_behavior = {
                    "name": "enable_gzip",
                    "enabled": True,
                    "description": "Compress content",
                    "target": {},
                }

                unique_key = behavior_key(azion_behavior)
                # Unique key for enable_gzip
                if unique_key in seen_behaviors:
                    logging.debug(f"[rules_engine][process_behaviors] already processed behavior {behavior_name}, key {unique_key}. Skipping.")
                    continue

                azion_behaviors.append(azion_behavior)
                seen_behaviors.add(unique_key)

            # Handle true client ip (add_request_header)
            if options.get("enableTrueClientIp", False) == True:
                trueClientIpHeader = options.get("trueClientIpHeader", "")
                if trueClientIpHeader:
                    azion_behavior = {
                        "name": "add_request_header",
                        "enabled": True,
                        "description": f"Add host header to {trueClientIpHeader}",
                        "target": { "target": '"' + f'{trueClientIpHeader}: ' + "$${remote_addr}" + '"' },
                        "phase": "request",
                        "akamai_behavior": "trueClientIpHeader"
                    }

                    unique_key = behavior_key(azion_behavior)
                    # Unique key for add_request_header
                    if unique_key in seen_behaviors:
                        logging.debug(f"[rules_engine][process_behaviors] already processed behavior {behavior_name}, key {unique_key}. Skipping.")
                        continue

                    azion_behaviors.append(azion_behavior)
                    seen_behaviors.add(unique_key)
            continue
        

        # Handle special behavior: set_host_header
        if mapping["azion_behavior"] == "set_host_header":
            host_header = map_forward_host_header(options)
            azion_behavior = {
                "name": "set_host_header",
                "enabled": True,
                "description": behavior.get("description", f"Set host header to {host_header}"),
                "target": { "host_header": host_header },
                "phase": "request"
            }

            unique_key = behavior_key(azion_behavior)
            # Unique key for set_host_header
            if unique_key in seen_behaviors:
                logging.debug(f"[rules_engine][process_behaviors] already processed behavior {behavior_name}, key {unique_key}. Skipping.")
                continue

            azion_behaviors.append(azion_behavior)
            seen_behaviors.add(unique_key)
            continue

        # Handle special behavior: capture_match_groups
        if mapping["azion_behavior"] == "capture_match_groups":
            behaviors = behavior_capture_match_groups(options, mapping, behavior)
            for entry in behaviors:
                if entry.get("name") == "setvar":
                    context['envvar'] = entry
                    print(f"Set variable '{entry['var']}' in rule '{rule_name}' processing context")
                    continue

                # Create a unique key to track this behavior
                unique_key = behavior_key(entry)
                if unique_key in seen_behaviors:
                    logging.debug(f"[rules_engine][process_behaviors] already processed behavior {behavior_name}, key {unique_key}. Skipping.")
                    continue

                azion_behaviors.append(entry)
                seen_behaviors.add(unique_key)
            continue

        # Handle special behavior: run_function
        if mapping["azion_behavior"] == "run_function":
            # Check if we have a function mapping for this behavior
            cloudlet_id = options.get("cloudletPolicy", {}).get("id", "")
            function_name = options.get("cloudletPolicy", {}).get("name", "")
            main_setting_name = context.get("main_setting_name", "unnamed")

            _, global_settings = azion_resources.query_azion_resource_by_type('global_settings')
            function_map = global_settings.get("attributes",{}).get("function_map", None)
            mapped_function = find_function(function_map, cloudlet_id)
            
            if mapped_function:
                # Use the mapped function
                function_id = mapped_function.get("function_id")
                function_args = mapped_function.get("args", [])
                
                logging.info(f"[rules_engine][process_behaviors] Using Function ID: {function_id} for behavior '{ak_behavior_name}'")
                
                # Create edge function instance reference
                instance_name = sanitize_name(f"{rule_name}_{function_name}_instance")
                environment = context.get("environment", "production")
                if environment != "production":
                    instance_name = f"{instance_name}_{environment}"
                edge_function_instance = create_edge_function_instance(
                    main_setting_name,
                    instance_name,
                    function_id,
                    function_args
                )
                
                # Add the edge function instance to the resources
                if edge_function_instance:
                    azion_resources.append(edge_function_instance)
                    function_instance_ref = f"azion_edge_application_edge_functions_instance.{instance_name}"

                    # Create behavior to run the edge function
                    azion_behavior = {
                        "name": "run_function",
                        "enabled": True,
                        "description": f"Function {function_name} mapped function {function_id}",
                        "phase": "request",
                        "akamai_behavior": ak_behavior_name,
                        "target": {
                            "target": f"azion_edge_application_edge_functions_instance.{instance_name}.id"
                        }
                    }
                    unique_key = behavior_key(azion_behavior)
                    if unique_key in seen_behaviors:
                        logging.debug(f"[rules_engine][process_behaviors] already processed behavior {behavior_name}, key {unique_key}. Skipping.")
                        continue
                    azion_behaviors.append(azion_behavior)
                    seen_behaviors.add(unique_key)
                    depends_on.add(function_instance_ref)

                    # Handle special case for forwardRewrite
                    if mapping.get("akamai_behavior") == "forwardRewrite":
                        forward_rewrite_name = compact_and_sanitize(f"{rule_name}_{rule_index}_{function_name}")
                        resource = process_forward_rewrite(context,
                                                         forward_rewrite_name,
                                                         rule_index,
                                                         main_setting_name,
                                                         depends_on)
                        if resource:
                            resources = context.get("resources", [])
                            resources.append(resource[0])
                            logging.info(f"[rules_engine] Rule engine resource created for rule: '{rule_name}'")

                    continue
            else:
                # No mapping found Edge Function for Akamai Cloudlet
                logging.warning(f"[rules_engine][process_behaviors] No Edge Function mapping found for Cloudlet on behavior: '{ak_behavior_name}' Skipping.")

            continue

        # Handle special behavior: rewrite_request
        if mapping["azion_behavior"] == "rewrite_request":
            entries = behavior_rewrite_request(options, rule_name)
            for item in entries:
                # Create a unique key to track this behavior
                unique_key = behavior_key(item)
                if unique_key in seen_behaviors:
                    logging.debug(f"[rules_engine][process_behaviors] already processed behavior {behavior_name}, key {unique_key}. Skipping.")
                    continue

                azion_behaviors.append(item)
                seen_behaviors.add(unique_key)
            continue            

        # Skip if we've already processed this behavior type
        if behavior_name in seen_behaviors:
            logging.debug(f"[rules_engine][process_behaviors] already processed behavior {behavior_name}, key {unique_key}. Skipping.")
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
                        logging.error(
                            f"[rules_engine][process_behaviors] Error processing target for key '{target_key}' in behavior '{behavior_name}': {e}"
                        )
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

        unique_key = behavior_key(azion_behavior)
        if unique_key in seen_behaviors:
            logging.debug(f"[rules_engine][process_behaviors] already processed behavior {behavior_name}, key {unique_key}. Skipping.")
            continue
        azion_behaviors.append(azion_behavior)
        seen_behaviors.add(unique_key)

    # Add consolidated cache policy if we collected any options
    if cache_policy_options:
        azion_behaviors.append({
            "name": "set_cache_policy",
            "enabled": True,
            "target": cache_policy_options,
            "description": "Cache policy consolidated from multiple behaviors"
        })

    return azion_behaviors, depends_on
