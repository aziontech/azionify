from .utils import (
    get_input_hostname, 
    get_redirect_target, 
    is_positive_operator,
    format_file_extension_pattern,
    format_path_pattern,
    format_filename_pattern,
    format_header_name,
    get_http_header_varname,
    format_varitens_pattern
)

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
            "azion_condition": "$${request_uri}", 
            "azion_operator": lambda options: "matches" if is_positive_operator(options.get("matchOperator")) else "does_not_match",
            "input_value": format_file_extension_pattern
        },
        "path": {
            "azion_condition": "$${uri}", 
            "azion_operator": lambda options: "matches" if is_positive_operator(options.get("matchOperator")) else "does_not_match",
            "input_value": format_path_pattern
        },
        "filename": {
            "azion_condition": "$${request_uri}", 
            "azion_operator": lambda options: "matches" if is_positive_operator(options.get("matchOperator")) else "does_not_match",
            "input_value": format_filename_pattern
        },
        "hostname": {
            "name": "hostname",
            "azion_condition": "$${host}", 
            "azion_operator": lambda options: "matches" if is_positive_operator(options.get("matchOperator")) else "does_not_match",
            "input_value": lambda values: f'{get_input_hostname(values)}'
        },
        "requestProtocol": {
            "name": "requestProtocol",
            "azion_condition": "$${scheme}", 
            "azion_operator": "is_equal",
            "input_value": lambda values: f'{values[0].lower()}'
        },
        "matchVariable": {
            "name": "matchVariable",
            "azion_condition": get_http_header_varname, 
            "azion_operator": lambda options: "matches" if is_positive_operator(options.get("matchOperator")) else "does_not_match",
            "input_value": format_varitens_pattern,
            "phase": "request"
        },
        "deviceGroup": {"azion_condition": "$${device_group}", "azion_operator": "is_equal"},
        "geoip_country_code": {"azion_condition": "$${geoip_country_code}", "azion_operator": "is_equal"},
        "contentType": {
            "name": "contentType",
            "azion_condition": "$${request_uri}", 
            "azion_operator": "starts_with",
            "input_value": lambda values: "/" 
            #lambda values: r"(%s)" % "|".join(values).replace('/', r'\\/').replace('.', r'\\.')
        },
        "queryString": {"azion_condition": "$${args}", "azion_operator": "matches"},
        "queryStringParam": {"azion_condition": "$${arg_param}", "azion_operator": "matches"},
        "cookie": {"azion_condition": "$${cookie_name}", "azion_operator": "matches"},
        "requestHeader": {"azion_condition": "$${http_header}", "azion_operator": None},
        "clientIP": {"azion_condition": "$${remote_addr}", "azion_operator": "matches"},
        "requestMethod": {"azion_condition": "$${request_method}", "azion_operator": "matches"},
        "requestUri": {"azion_condition": "$${request_uri}", "azion_operator": "matches"},
        "geoipCity": {"azion_condition": "$${geoip_city}", "azion_operator": "matches"},
        "geoipCityCountryCode": {"azion_condition": "$${geoip_city_country_code}", "azion_operator": "matches"},
        "geoipCityCountryName": {"azion_condition": "$${geoip_city_country_name}", "azion_operator": "matches"},
        "geoipContinentCode": {"azion_condition": "$${geoip_continent_code}", "azion_operator": "matches"},
        "geoipRegion": {"azion_condition": "$${geoip_region}", "azion_operator": "matches"},
        "geoipRegionName": {"azion_condition": "$${geoip_region_name}", "azion_operator": "matches"},
        "cloudletsOrigin": {
            "azion_condition": "$${http_x_az_forward_rewrite_origin}", 
            "azion_operator": "is_equal",
            "conditional": "if",
            "phase": "request",
            "input_value": ''
        },
        
        # Response Phase Variables
        "responseHeader": {
            "azion_condition": "$${sent_http_header}",
            "azion_operator": "matches",
            "phase": "response",
            "name": "filter_response_header"
        },
        "statusCode": {"azion_condition": "$${status}", "azion_operator": "matches", "phase": "response"},
        "upstreamAddress": {"azion_condition": "$${upstream_addr}", "azion_operator": "matches", "phase": "response"},
        "upstreamCookie": {"azion_condition": "$${upstream_cookie_name}", "azion_operator": "matches", "phase": "response"},
        "upstreamHeader": {"azion_condition": "$${upstream_http_header}", "azion_operator": "matches", "phase": "response"},
        "upstreamStatus": {"azion_condition": "$${upstream_status}", "azion_operator": "matches", "phase": "response"},
        "removeVary": {
            "name": "filter_response_header",
            "azion_condition": "$${request_uri}",
            "azion_operator": "starts_with",
            "input_value": "/",
            "conditional": "if",
            "phase": "response",
            "akamai_behavior": "removeVary",
        },
    },
    "behaviors": {
        # Compression
        "gzipResponse": {"azion_behavior": "enable_gzip", "phase": "response", "akamai_behavior": "gzipResponse"},

        # Cache Control
        "noCaching": {"azion_behavior": "bypass_cache_phase","phase": "request", "akamai_behavior": "noCaching"},
        "caching": {
            "azion_behavior": "set_cache_policy",
            "phase": "request",
            "target": {
                "browser_cache_settings": "override",
                "browser_cache_settings_maximum_ttl": "ttl",
                "cdn_cache_settings": "override",
                "cdn_cache_settings_maximum_ttl": "ttl",
                "is_slice_configuration_enabled": False,
                "is_slice_edge_caching_enabled": False,
                "slice_configuration_range": 1024,
                "enable_stale_cache": lambda options: not options.get("mustRevalidate", False),
            },
        },
        "bypassCache": {"azion_behavior": "bypass_cache_phase","phase": "request", "akamai_behavior": "bypassCache"},
        "prefreshCache": {
            "azion_behavior": "set_cache_policy",
            "target": {
                "prefresh_value": "prefreshval"
            },
            "phase": "request",
            "akamai_behavior": "prefreshCache"
        },
        #"downstreamCache": {
        #    "azion_behavior": "set_cache_policy",
        #    "target": {
        #        "allow_behavior": "allowBehavior",
        #        "behavior": "behavior",
        #        "send_headers": "sendHeaders",
        #        "send_private": "sendPrivate"
        #    }
        #},

        # Cookies
        "modifyOutgoingResponseCookie": {
            "azion_behavior": "set_cookie",
            "target": {"name": "cookie_name", "value": "cookie_value"},
            "phase": "response",
            "akamai_behavior": "modifyOutgoingResponseCookie"
        },
        "modifyIncomingRequestCookie": {
            "azion_behavior": "add_request_cookie",
            "target": {"name": "cookie_name", "value": "cookie_value"},
            "phase": "request",
            "akamai_behavior": "modifyIncomingRequestCookie"
        },
        "removeResponseCookie": {
            "azion_behavior": "filter_response_cookie",
            "target": "cookie_name",
            "phase": "response",
            "akamai_behavior": "removeResponseCookie"
        },
        "removeRequestCookie": {
            "azion_behavior": "filter_request_cookie", 
            "target": "cookie_name", 
            "phase": "request", 
            "akamai_behavior": "removeRequestCookie"
        },
        "forwardCookies": {"azion_behavior": "forward_cookies", "phase": "request", "akamai_behavior": "forwardCookies"},
        "cookies": {
            "logCookies": {
                "azion_behavior": "add_request_header", 
                "target": {
                    "name": "Set-Cookie", 
                    "value": "log_cookie"
                },
                "phase": "request",
                "akamai_behavior": "logCookies"
            },
        },

        # Headers (adding/removing/modifying)
        "modifyOutgoingResponseHeader": {
            "azion_behavior": lambda options: "filter_response_header" if options.get("action").upper() == "DELETE" else "add_response_header",
            "target": {
                "target": format_header_name
            },
            "phase": "response",
            "akamai_behavior": "modifyOutgoingResponseHeader"
        },
        "removeOutgoingResponseHeader": {
            "azion_behavior": "filter_response_header",
            "target": "header_name",
            "phase": "response",
            "akamai_behavior": "removeOutgoingResponseHeader"
        },
        "allowTransferEncoding": {
            "azion_behavior": lambda options: None if options.get("enabled", True) else "filter_request_header",
            "target": {
                "name": "Transfer-Encoding",
                "target": "Transfer-Encoding"
            },
            "phase": "request",
            "akamai_behavior": "allowTransferEncoding"
        },
        "removeVary": {
            "azion_behavior": "filter_response_header",
            "target": {"target": "Vary"},
            "phase": "response",
            "akamai_behavior": "removeVary"
        },

        # Redirects
        "redirect": {
            "azion_behavior": 
                lambda options: "redirect_http_to_https" if options.get("responseCode", 301) not in [301, 302] else f"redirect_to_{options.get('responseCode', 301)}",
             "target": {
                "target": get_redirect_target
             },
             "phase": "request",
             "akamai_behavior": "redirect"
        },
        "redirectPermanent": {"azion_behavior": "redirect_http_to_https", "target": "location", "phase": "request", "akamai_behavior": "redirectPermanent"},
        "redirectTemporary": {"azion_behavior": "redirect_http_to_https", "target": "location", "phase": "request", "akamai_behavior": "redirectTemporary"},
        "redirectToHttps": {"azion_behavior": "redirect_http_to_https", "phase": "request", "akamai_behavior": "redirectToHttps"},

        # Origin
        "origin": {
            "azion_behavior": "set_origin",
            "target": {
                "enabled": "enabled"
            },
            "phase": "request",
            "akamai_behavior": "origin"
        },
        "cloudletsOrigin": {
            "azion_behavior": "set_origin",  # Use custom origin behavior in Azion
            "target": {
                "addresses": lambda options: [{"address": options.get("originId"), "weight": 1}],
                "origin_type": "single_origin",
            },
            "phase": "request",
            "akamai_behavior": "cloudletsOrigin"
        },

        # Response
        "respondWithNoContent": {"azion_behavior": "no_content", "phase": "request", "akamai_behavior": "respondWithNoContent"},

        # Edge Functions
        "edgeWorker": {"azion_behavior": "run_function", "target": "function_id", "akamai_behavior": "edgeWorker"},
        "run_function": {"azion_behavior": "run_function", "target": "function_id", "akamai_behavior": "run_function"},
        #"webApplicationFirewall": {"azion_behavior": "run_function", "target": {"name": "WAF"}},

        # Image Optimization
        "imageManager": {"azion_behavior": "optimize_images", "phase": "request", "akamai_behavior": "imageManager"},
        #"prefetch": {
        #    "azion_behavior": "optimize_images",
        #    "target": {},
        #    "akamai_behavior": "prefetch"
        #},
        #"prefetchable": {
        #    "azion_behavior": "optimize_images",
        #    "target": {},
        #    "akamai_behavior": "prefetchable"
        #},

        # URL Rewrite
        "rewriteUrl": {
            "azion_behavior": "rewrite_request",
            "target": {
                "target": ''
            },
            "phase": "request",
            "akamai_behavior": "rewriteUrl"
        },
        "rewrite_request": {
            "azion_behavior": "rewrite_request", 
            "target": "path",
            "phase": "request",
            "akamai_behavior": "rewrite_request"
        },
        "baseDirectory": {
            "azion_behavior": "rewrite_request",
            "target": {
                "target": lambda options: f"{options.get('value', '')}$${{uri}}", # Concatenate baseDirectory with original path
            },
            "phase": "request",
            "akamai_behavior": "baseDirectory"
        },

        # Special Cases
        "deliver": {"azion_behavior": "deliver"},
        "deny": {"azion_behavior": "deny", "phase": "request", "akamai_behavior": "deny"},
        "setVariable": {
            "azion_behavior": "capture_match_groups",
            "target": {
                "captured_array": "variableName",
                "subject": "dynamic_subject",
                "regex": "regex"
            },
            "phase": "request",
            "akamai_behavior": "setVariable"
        },

        #Cloudlets
        "edgeRedirector": {
            "azion_behavior": "run_function",
            "target": "function_id",
            "phase": "request",
            "akamai_behavior": "edgeRedirector"
        },
        "forwardRewrite": {
            "azion_behavior": "run_function",
            "target": "function_id",
            "phase": "request",
            "akamai_behavior": "forwardRewrite"
        }
    },
    "advanced_behaviors": {
        "prefetch": {"azion_behavior": "prefetch_assets"},
        "webSocket": {"azion_behavior": "websocket"}
    }
}
