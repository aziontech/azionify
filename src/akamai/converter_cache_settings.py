import logging
from typing import Dict, Any, Optional
from azion_resources import AzionResource
from utils import parse_ttl

def create_cache_setting(azion_resources: AzionResource, rule: Dict[str, Any], main_setting_name: str) -> Dict[str, Any]:
    """
    Creates a single Azion cache setting resource.
    """
    logging.info(f"Creating cache setting for rule: {rule.get('name', 'Unnamed Rule')}")
    caching_behavior = next((b for b in rule.get("behaviors", []) if b.get("name") == "caching"), None)
    if caching_behavior:
        logging.info("Cache behavior found. Generating resource.")

        # Extract and validate TTL
        ttl = 0
        try:
            ttl = caching_behavior.get("options", {}).get("ttl", 3600)
            ttl = parse_ttl(ttl)
        except (ValueError, TypeError):
            logging.warning(f"Invalid TTL value: {ttl}, defaulting to 3600")
            ttl = 3600

        if ttl > 31536000:
            logging.warning(f"Invalid TTL value: {ttl}, defaulting to 31536000 (1 year)")
            ttl = 31536000

        if ttl < 0:
            logging.warning(f"Invalid TTL value: {ttl}, defaulting to 0")
            ttl = 0

        return {
            "type": "azion_edge_application_cache_setting",
            "name": main_setting_name,
            "attributes": {
                "cache_settings": {
                    "name": rule.get("name", "Default Cache Setting"),
                    "enable_stale_cache": True,
                    "browser_cache_settings": "override",
                    "browser_cache_settings_maximum_ttl": int(ttl),
                    "cdn_cache_settings": "override",
                    "cdn_cache_settings_maximum_ttl": int(ttl)
                },
                "edge_application_id": f"azion_edge_application_main_setting.{main_setting_name}.edge_application.application_id",
            },
        }
    logging.warning("No caching behavior found. Skipping cache setting creation.")
    return None