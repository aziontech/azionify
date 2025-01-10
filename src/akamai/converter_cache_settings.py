import logging
from typing import Dict, Any, List, Optional
from azion_resources import AzionResource
from utils import parse_ttl, sanitize_name

def map_allow_behavior_to_azion(allow_behavior: str, ttl: int) -> Dict[str, Any]:
    """
    Maps the 'allowBehavior' behavior from Akamai to the Azion cache settings configuration.

    Parameters:
        allow_behavior (str): The value of 'allowBehavior' from Akamai (e.g., "ALLOW" or "LESSER").
        ttl (int): The TTL configured in Akamai.

    Returns:
        Dict[str, Any]: A dictionary with cache settings for Azion.
    """
    # Default Azion cache settings with 'honor' for browser cache and 'override' for CDN cache
    cache_settings = {
        "browser_cache_settings": "honor",  # Default value for browser cache
        "browser_cache_settings_maximum_ttl": 0,
        "cdn_cache_settings": "override",  # Default value for CDN cache
        "cdn_cache_settings_maximum_ttl": ttl,
        "adaptive_delivery_action": "ignore",
        "cache_by_query_string": "ignore",
        "cache_by_cookies": "ignore",
        "enable_stale_cache": 'false'
    }

    if allow_behavior == "ALLOW":
        # If 'ALLOW', map to 'override' for browser cache and apply TTL
        cache_settings["browser_cache_settings"] = "override"
        cache_settings["browser_cache_settings_maximum_ttl"] = ttl
        logging.info(f"Mapped 'ALLOW' to browser_cache_settings: 'override' with TTL: {ttl}")
    
    elif allow_behavior == "LESSER":
        # If 'LESSER', keep the default 'honor' for browser cache
        cache_settings["browser_cache_settings"] = "honor"
        cache_settings["browser_cache_settings_maximum_ttl"] = 0
        logging.info("Mapped 'LESSER' to browser_cache_settings: 'honor'")

    return cache_settings


def create_cache_setting(azion_resources: AzionResource, rules: List[Dict[str, Any]], main_setting_name: str, cache_name: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Creates a single Azion cache setting resource.

    Parameters:
        rules (List[Dict[str, Any]]): List of rules extracted from Akamai configuration.
        main_setting_name (str): Name of the main Azion edge application resource.
        cache_name (Optional[str]): Name of the cache setting resource.

    Returns:
        Dict[str, Any]: Azion-compatible cache setting resource.
    """
    # Extract and validate caching behavior
    caching_behavior = next((rule['options'] for rule in rules if rule.get("name") == "caching"), None)
    if not caching_behavior:
        logging.warning("No caching behavior found in rule.")
        return None

    name = sanitize_name(cache_name if cache_name else caching_behavior.get('name', 'default_caching'))
    logging.info(f"Creating cache setting for rule: {name}")

    # Extract and validate TTL
    ttl = 0
    try:
        ttl = caching_behavior.get("ttl", '3600')
        ttl = parse_ttl(ttl)
    except (ValueError, TypeError):
        logging.warning(f"Invalid TTL value: {ttl}, defaulting to 3600")
        ttl = 3600

    # Enforcing max TTL of 1 year (31536000 seconds)
    if ttl > 31536000:
        logging.warning(f"TTL value {ttl} exceeds 1 year, defaulting to 31536000 (1 year)")
        ttl = 31536000

    # Enforcing min TTL to 0 if less than 0
    if ttl < 0:
        logging.warning(f"TTL value {ttl} is negative, defaulting to 0")
        ttl = 0

    # Process 'downstreamCache' behavior
    downstreamCache = next((rule['options'] for rule in rules if rule.get("name") == "downstreamCache"), None)
    if downstreamCache:
        if downstreamCache.get("allowBehavior", "ALLOW") == "LESSER":
            cache_attributes = map_allow_behavior_to_azion("LESSER", ttl)
        else:
            cache_attributes = map_allow_behavior_to_azion("ALLOW", ttl)
    else:
        cache_attributes = map_allow_behavior_to_azion("DEFAULT", ttl)

    # Process 'prefreshCache' behavior
    prefreshCache = next((rule['options'] for rule in rules if rule.get("name") == "prefreshCache"), None)
    if prefreshCache:
        if prefreshCache.get("enabled", False):
            cache_attributes["enable_stale_cache"] = 'true'
        else:
            cache_attributes["enable_stale_cache"] = 'false'
    else:
        cache_attributes["enable_stale_cache"] = 'false'


    #depends_on
    depends_on = [f"azion_edge_application_main_setting.{main_setting_name}"]
    origin = azion_resources.query_azion_resource_by_type("azion_edge_application_origin", name)
    if not origin:
        logging.warning(f"Origin resource not found for rule: {name}")
    else:
        depends_on.append(f"azion_edge_application_origin.{name}")

    # Construct the cache setting resource
    cache_setting = {
        "type": "azion_edge_application_cache_setting",
        "name": name,
        "attributes": {
            "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.edge_application.application_id",
            "cache_settings": cache_attributes,
            "depends_on": depends_on,
        },
    }

    logging.info(f"Cache setting created for rule: {name}")
    return cache_setting

