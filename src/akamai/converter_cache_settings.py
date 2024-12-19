import logging
from typing import Dict, Any, Optional
from azion_resources import AzionResource
from utils import parse_ttl, sanitize_name

from typing import Dict, Any
import logging

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

    else:
        # For any other unexpected value, default to 'honor'
        cache_settings["browser_cache_settings"] = "honor"
        cache_settings["browser_cache_settings_maximum_ttl"] = 0
        logging.warning(f"Unexpected allow_behavior '{allow_behavior}', defaulting to 'honor'")

    return cache_settings


def create_cache_setting(azion_resources: AzionResource, behaviors: Dict[str, Any], main_setting_name: str) -> Optional[Dict[str, Any]]:
    """
    Creates a single Azion cache setting resource.
    """

    # Extract and validate caching behavior
    caching_behavior = next((b for b in behaviors.get("behaviors", []) if b.get("name") == "caching"), None)
    if not caching_behavior:
        logging.warning("No caching behavior found in rule.")
        return None

    name = sanitize_name(behaviors.get('name', 'Unnamed Rule'))
    logging.info(f"Creating cache setting for rule: {name}")

    # Extract and validate TTL
    ttl = 0
    try:
        ttl = caching_behavior.get("options", {}).get("ttl", 3600)
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

    cache_attributes = map_allow_behavior_to_azion(caching_behavior.get("options", {}).get("allowBehavior", "ALLOW"), ttl)
    
    prefreshCache = next((b for b in behaviors.get("behaviors", []) if b.get("name") == "prefreshCache"), None)
    if prefreshCache:
        # Process 'prefreshCache' behavior
        if prefreshCache.get("options", {}).get("enabled", False):
            cache_attributes["enable_stale_cache"] = 'true'
        else:
            cache_attributes["enable_stale_cache"] = 'false'
    else:
        cache_attributes["enable_stale_cache"] = 'false'

    # Construct the cache setting resource
    cache_setting = {
        "type": "azion_edge_application_cache_setting",
        "name": name,
        "attributes": {
            "cache_settings": cache_attributes,
            "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.edge_application.application_id",
        },
    }

    logging.info(f"Cache setting created for rule: {name}")
    print(f'-$$$$$->DEBUG: {cache_setting}')
    return cache_setting
    
    return None
