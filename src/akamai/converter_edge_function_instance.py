from typing import Dict, Any, Optional
import json
import logging

def create_edge_function_instance(
        main_setting_name: str,
        instance_name: str,
        edge_function_id: str,
        function_args: Any = None
    ) -> Optional[Dict[str, Any]]:
    """
    Creates an Azion Edge Function Instance resource.

    Args:
        main_setting_name (str): Name of the main setting resource to link this instance to.
        instance_name (str): The name of the instance.
        edge_function_id (str): The ID of the edge function.
        function_args (Any, optional): Function arguments. Can be a JSON string, dict, or list of configurations.

    Returns:
        Optional[Dict[str, Any]]: Azion-compatible Edge Function Instance resource.
    """
    
    # Handle different types of args
    if function_args is None:
        args = {}
    elif isinstance(function_args, str):
        try:
            args = json.loads(function_args)
        except json.JSONDecodeError:
            logging.warning(f"Warning: Invalid JSON in function_args: {function_args}. Using empty dict.")
            args = {}
    else:
        # If it's already a dict or list, use it as is
        args = function_args
    
    # Convert edge_function_id to int if it's a string number
    try:
        edge_function_id_int = int(edge_function_id)
    except (ValueError, TypeError):
        edge_function_id_int = edge_function_id
    
    function_instance_resource = {
        "type": "azion_edge_application_edge_functions_instance",
        "name": instance_name,
        "attributes": {
            "name": instance_name,
            "edge_application_name": main_setting_name,
            "edge_function_id": edge_function_id_int,
            "args": args,
            "depends_on": [
                f"azion_edge_application_main_setting.{main_setting_name}"
            ]
        }
    }
    return function_instance_resource
