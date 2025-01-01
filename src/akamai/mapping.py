from .utils import replace_variables

# Mapping for Akamai to Azion behavior/criteria conversions
MAPPING = {
    "caching": {
        "CACHE": {"azion_behavior": "caching", "ttl": "ttl"},
        "NO_CACHE": {"azion_behavior": "caching", "enabled": False},
        "MAX_AGE": {"azion_behavior": "set_cache_policy", "target": {"name": "Max Age Cache", "max_age": "ttl"}},
        "cacheError": {"azion_behavior": "set_cache_policy", "target": {"name": "Error Cache", "max_age": "ttl"}},
    },
    "origin": {
        "CUSTOMER": {"azion_origin_type": "custom"},
    },
    "redirect": {
        "destinationPath": {"azion_behavior": "redirect_to_301", "target": "destinationPath"},
        "destinationPathOther": {"azion_behavior": "redirect_to_302", "target": "destinationPathOther"},
    },
    "headers": {
        "addHeader": {"azion_behavior": "add_request_header", "target": {"name": "header", "value": "value"}},
        "removeHeader": {"azion_behavior": "filter_request_header", "target": "header"},
        "modifyOutgoingResponseHeader": {"azion_behavior": "set_host_header", "target": "host_header"},
        "modifyIncomingRequestHeader": {"azion_behavior": "set_host_header", "target": "host_header"},
    },
    "criteria": {
        # Request Phase Variables
        "fileExtension": {
            "azion_condition": "$${request_uri}}", 
            "azion_operator": "matches",
            "input_value": lambda values: r"\\.(%s)(\\?.*)?$" % "|".join(values).replace('/', r'\\/')
        },
        "path": {
            "azion_condition": "$${uri}", 
            "azion_operator": "matches",
            "input_value": lambda values: r"(%s)" % "|".join(values).replace('/', r'\\/')
        },
        "hostname": {"azion_condition": "$${host}", "azion_operator": "is_equal"},
        "requestProtocol": {"azion_condition": "$${scheme}", "azion_operator": "is_equal"},
        "deviceGroup": {"azion_condition": "$${device_group}", "azion_operator": "is_equal"},
        "geoip_country_code": {"azion_condition": "$${geoip_country_code}", "azion_operator": "is_equal"},
        "contentType": {
            "azion_condition": "$${content_type}", 
            "azion_operator": "matches",
            "input_value": lambda values: r"(%s)" % "|".join(values).replace('/', r'\\/').replace('.', r'\\.')
        },
        "queryString": {"azion_condition": "$${args}", "azion_operator": "matches"},
        "queryStringParam": {"azion_condition": "$${arg_param}", "azion_operator": "matches"},
        "cookie": {"azion_condition": "$${cookie_name}", "azion_operator": "matches"},
        "requestHeader": {"azion_condition": "$${http_header}", "azion_operator": "matches"},
        "clientIP": {"azion_condition": "$${remote_addr}", "azion_operator": "matches"},
        "requestMethod": {"azion_condition": "$${request_method}", "azion_operator": "matches"},
        "requestUri": {"azion_condition": "$${request_uri}", "azion_operator": "matches"},
        "geoipCity": {"azion_condition": "$${geoip_city}", "azion_operator": "matches"},
        "geoipCityCountryCode": {"azion_condition": "$${geoip_city_country_code}", "azion_operator": "matches"},
        "geoipCityCountryName": {"azion_condition": "$${geoip_city_country_name}", "azion_operator": "matches"},
        "geoipContinentCode": {"azion_condition": "$${geoip_continent_code}", "azion_operator": "matches"},
        "geoipRegion": {"azion_condition": "$${geoip_region}", "azion_operator": "matches"},
        "geoipRegionName": {"azion_condition": "$${geoip_region_name}", "azion_operator": "matches"},
        "cloudletsOrigin": {"azion_condition": "$${upstream_addr}", "azion_operator": "matches"},
        
        # Response Phase Variables
        "responseHeader": {"azion_condition": "$${sent_http_header}", "azion_operator": "matches", "phase": "response"},
        "statusCode": {"azion_condition": "$${status}", "azion_operator": "matches", "phase": "response"},
        "upstreamAddress": {"azion_condition": "$${upstream_addr}", "azion_operator": "matches", "phase": "response"},
        "upstreamCookie": {"azion_condition": "$${upstream_cookie_name}", "azion_operator": "matches", "phase": "response"},
        "upstreamHeader": {"azion_condition": "$${upstream_http_header}", "azion_operator": "matches", "phase": "response"},
        "upstreamStatus": {"azion_condition": "$${upstream_status}", "azion_operator": "matches", "phase": "response"},
        "removeVary": {
            "azion_condition": "$${request_uri}",
            "azion_operator": "starts_with",
            "input_value": "/",
            "conditional": "if",
            "phase": "response"
        },
    },
    "behaviors": {
        # Compression
        "gzipResponse": {"azion_behavior": "enable_gzip"},

        # Cache Control
        "noCaching": {"azion_behavior": "bypass_cache_phase"},
        "caching": {
            "azion_behavior": "set_cache_policy",
            "target": {
                "browser_cache_settings": "override",
                "browser_cache_settings_maximum_ttl": "ttl",
                "cdn_cache_settings": "override",
                "cdn_cache_settings_maximum_ttl": "ttl",
                "enable_stale_cache": lambda options: not options.get("mustRevalidate", False),
            },
        },
        "bypassCache": {"azion_behavior": "bypass_cache_phase"},
        "prefreshCache": {
            "azion_behavior": "set_cache_policy",
            "target": {
                "prefresh_value": "prefreshval"
            }
        },
        "downstreamCache": {
            "azion_behavior": "set_cache_policy",
            "target": {
                "allow_behavior": "allowBehavior",
                "behavior": "behavior",
                "send_headers": "sendHeaders",
                "send_private": "sendPrivate"
            }
        },

        # Cookies
        "modifyOutgoingResponseCookie": {"azion_behavior": "set_cookie", "target": {"name": "cookie_name", "value": "cookie_value"}},
        "modifyIncomingRequestCookie": {"azion_behavior": "add_request_cookie", "target": {"name": "cookie_name", "value": "cookie_value"}},
        "removeResponseCookie": {"azion_behavior": "filter_response_cookie", "target": "cookie_name"},
        "removeRequestCookie": {"azion_behavior": "filter_request_cookie", "target": "cookie_name"},
        "forwardCookies": {"azion_behavior": "forward_cookies"},
        "cookies": {
            "logCookies": {"azion_behavior": "add_request_header", "target": {"name": "Set-Cookie", "value": "log_cookie"}},
        },

        # Headers (adding/removing/modifying)
        "modifyOutgoingResponseHeader": {"azion_behavior": "add_response_header", "target": {"name": "header_name", "value": "header_value"}},
        "removeOutgoingResponseHeader": {"azion_behavior": "filter_response_header", "target": "header_name"},
        "allowTransferEncoding": {
            "azion_behavior": "add_request_header",
            "target": {
                "name": "Transfer-Encoding",
                "target": lambda options: '"Transfer-Encoding: chunked"' if options.get("enabled", True) else None
            }
        },
        "removeVary": {
            "azion_behavior": "filter_request_header",
            "target": {"name": "Remove Vary", "value": "Vary"}
        },

        # Redirects
        "redirect": {
            "azion_behavior": lambda options: "redirect_http_to_https" if options.get("destinationHostname") == "SAME_AS_REQUEST" else ("redirect_http_to_https" if options.get("responseCode") not in [301, 302] else f"redirect_to_{options.get('responseCode')}"),
             "target": {
                "target": lambda options: f"$${{scheme}}://{options.get('destinationHostnameOther', '$${{host}}')}/$${{request_uri}}"
             }
        },
        "redirectPermanent": {"azion_behavior": "redirect_http_to_https", "target": "location"},
        "redirectTemporary": {"azion_behavior": "redirect_http_to_https", "target": "location"},
        "redirectToHttps": {"azion_behavior": "redirect_http_to_https"},

        # Origin
        "origin": {
            "azion_behavior": "set_origin",
            "target": {
                "enabled": "enabled"
            }
        },
        "cloudletsOrigin": {
            "azion_behavior": "set_origin",  # Use custom origin behavior in Azion
            "target": {
                "addresses": lambda options: [{"address": options.get("originId"), "weight": 1}],
                "origin_type": "single_origin",
            }
        },

        # Response
        "respondWithNoContent": {"azion_behavior": "no_content"},

        # Edge Functions
        "edgeWorker": {"azion_behavior": "run_function", "target": "function_id"},
        "run_function": {"azion_behavior": "run_function", "target": "function_id"},
        "firewall": {
            "webApplicationFirewall": {"azion_behavior": "run_function", "target": {"name": "WAF"}},
        },

        # Image Optimization
        "imageManager": {"azion_behavior": "optimize_images"},
        "prefetch": {
            "azion_behavior": "optimize_images",
            "target": {
                "enabled": "enabled"
            }
        },
        "prefetchable": {
            "azion_behavior": "optimize_images",
            "target": {
                "enabled": "enabled"
            }
        },

        # URL Rewrite
        "rewriteUrl": {
            "azion_behavior": "rewrite_request",
            "target": {
                "target": lambda options: f"\"{replace_variables(options.get('targetUrl',''))}\""
            }
        },
        "rewrite_request": {
            "azion_behavior": "rewrite_request", 
            "target": "path"
        },
        "baseDirectory": {
            "azion_behavior": "rewrite_request",
            "target": {
                "target": lambda options: f"{options.get('baseDirectory', '')}$${{uri}}" # Concatenate baseDirectory with original path
            }
        },

        # Special Cases
        "allowPost": {"azion_behavior": "add_request_header", "target": {"name": "Allow", "value": "POST"}},
        "deliver": {"azion_behavior": "deliver"},
        "deny": {"azion_behavior": "deny"},
        "setVariable": {
            "azion_behavior": "capture_match_groups",
            "target": {
                "captured_array": "variableName",
                "subject": "dynamic_subject",
                "regex": "regex"
            }
        },
        "cpCode": {
            "azion_behavior": "add_request_header",
            "target": {
                "key": "cpCode",
                "value": lambda options: options.get("value", {}).get("id", "unknown")
            },
        },
    },
    "advanced_behaviors": {
        "sureroute": {"azion_behavior": "performance_optimization"},
        "sureRoute": {"azion_behavior": "performance_optimization"},
        "prefetch": {"azion_behavior": "prefetch_assets"},
        "webSocket": {"azion_behavior": "websocket"}
    }
}