variable "azion_api_token" {
    default     = null
    type        = string
    description = "Azion API token"
}

provider "azion" {
    api_token = var.azion_api_token
}

resource "azion_edge_application_main_setting" "blog_itau_com_br" {
    edge_application = {
        name                     = "blog.itau.com.br"
        supported_ciphers        = "TLSv1.2_2021"
        delivery_protocol        = "http,https"
        http_port                = [80]
        https_port               = [443]
        minimum_tls_version      = "tls_1_2"
        debug_rules              = false
        caching                  = true
        edge_functions           = true
        image_optimization       = true
        http3                    = false
        application_acceleration = true
        l2_caching               = false
        load_balancer            = false
        device_detection         = false
    }
}

resource "azion_edge_application_origin" "default" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id
    origin = {
        name        = "default"
        origin_type = "single_origin"
        addresses = [
            { "address" : "martechcmsless.cloud.itau.com.br" },
        ],
        origin_protocol_policy = "preserve"
        host_header = "martechcmsless.cloud.itau.com.br"
        origin_path = ""
        connection_timeout = 60
        timeout_between_bytes = 120
        hmac_authentication = false
        hmac_region_name = ""
        hmac_access_key = ""
        hmac_secret_key = ""
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
    ]
}

resource "azion_edge_application_origin" "martechcmsless" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id
    origin = {
        name        = "martechcmsless"
        origin_type = "single_origin"
        addresses = [
            { "address" : "martechcmsless.cloud.itau.com.br" },
        ],
        origin_protocol_policy = "preserve"
        host_header = "martechcmsless.cloud.itau.com.br"
        origin_path = ""
        connection_timeout = 60
        timeout_between_bytes = 120
        hmac_authentication = false
        hmac_region_name = ""
        hmac_access_key = ""
        hmac_secret_key = ""
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
    ]
}

resource "azion_edge_application_cache_setting" "offload_origin" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id
    cache_settings = {
        name = "offload_origin"
        browser_cache_settings = "honor"
        browser_cache_settings_maximum_ttl = 0
        cdn_cache_settings = "override"
        cdn_cache_settings_maximum_ttl = 3600
        adaptive_delivery_action = "ignore"
        cache_by_query_string = "ignore"
        cache_by_cookies = "ignore"
        enable_stale_cache = true
        is_slice_configuration_enabled = false
        is_slice_edge_caching_enabled = false
        slice_configuration_range = 1024
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
        azion_edge_application_origin.default,
    ]
}

resource "azion_edge_application_cache_setting" "css_and_javascript" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id
    cache_settings = {
        name = "css_and_javascript"
        browser_cache_settings = "honor"
        browser_cache_settings_maximum_ttl = 0
        cdn_cache_settings = "override"
        cdn_cache_settings_maximum_ttl = 172800
        adaptive_delivery_action = "ignore"
        cache_by_query_string = "ignore"
        cache_by_cookies = "ignore"
        enable_stale_cache = false
        is_slice_configuration_enabled = false
        is_slice_edge_caching_enabled = false
        slice_configuration_range = 1024
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
        azion_edge_application_origin.default,
    ]
}

resource "azion_edge_application_cache_setting" "fonts" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id
    cache_settings = {
        name = "fonts"
        browser_cache_settings = "honor"
        browser_cache_settings_maximum_ttl = 0
        cdn_cache_settings = "override"
        cdn_cache_settings_maximum_ttl = 86400
        adaptive_delivery_action = "ignore"
        cache_by_query_string = "ignore"
        cache_by_cookies = "ignore"
        enable_stale_cache = false
        is_slice_configuration_enabled = false
        is_slice_edge_caching_enabled = false
        slice_configuration_range = 1024
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
        azion_edge_application_origin.default,
    ]
}

resource "azion_edge_application_cache_setting" "images" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id
    cache_settings = {
        name = "images"
        browser_cache_settings = "honor"
        browser_cache_settings_maximum_ttl = 0
        cdn_cache_settings = "override"
        cdn_cache_settings_maximum_ttl = 86400
        adaptive_delivery_action = "ignore"
        cache_by_query_string = "ignore"
        cache_by_cookies = "ignore"
        enable_stale_cache = false
        is_slice_configuration_enabled = false
        is_slice_edge_caching_enabled = false
        slice_configuration_range = 1024
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
        azion_edge_application_origin.default,
    ]
}

resource "azion_edge_application_cache_setting" "files" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id
    cache_settings = {
        name = "files"
        browser_cache_settings = "honor"
        browser_cache_settings_maximum_ttl = 0
        cdn_cache_settings = "override"
        cdn_cache_settings_maximum_ttl = 86400
        adaptive_delivery_action = "ignore"
        cache_by_query_string = "ignore"
        cache_by_cookies = "ignore"
        enable_stale_cache = false
        is_slice_configuration_enabled = false
        is_slice_edge_caching_enabled = false
        slice_configuration_range = 1024
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
        azion_edge_application_origin.default,
    ]
}

resource "azion_edge_application_cache_setting" "other_static_objects" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id
    cache_settings = {
        name = "other_static_objects"
        browser_cache_settings = "honor"
        browser_cache_settings_maximum_ttl = 0
        cdn_cache_settings = "override"
        cdn_cache_settings_maximum_ttl = 86400
        adaptive_delivery_action = "ignore"
        cache_by_query_string = "ignore"
        cache_by_cookies = "ignore"
        enable_stale_cache = false
        is_slice_configuration_enabled = false
        is_slice_edge_caching_enabled = false
        slice_configuration_range = 1024
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
        azion_edge_application_origin.default,
    ]
}

resource "azion_edge_application_cache_setting" "html_pages" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id
    cache_settings = {
        name = "html_pages"
        browser_cache_settings = "honor"
        browser_cache_settings_maximum_ttl = 0
        cdn_cache_settings = "override"
        cdn_cache_settings_maximum_ttl = 3600
        adaptive_delivery_action = "ignore"
        cache_by_query_string = "ignore"
        cache_by_cookies = "ignore"
        enable_stale_cache = false
        is_slice_configuration_enabled = false
        is_slice_edge_caching_enabled = false
        slice_configuration_range = 1024
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
        azion_edge_application_origin.default,
    ]
}

resource "azion_edge_application_rule_engine" "default" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id

    results = {
        name        = "Default Rule"
        phase       = "default"
        description = "The Default Rule template contains all the necessary and recommended behaviors. Rules are evaluated from top to bottom and the last matching rule wins."
        behaviors = [
            {
                name = "set_origin"
                target_object = {
                    target = azion_edge_application_origin.default.id
                }
            },
            {
                name = "enable_gzip"
                target_object = {}
            },
            {
                name = "add_request_header"
                target_object = {
                    target = "True-Client-IP: $${remote_addr}"
                }
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${uri}"
                        operator    = "starts_with"
                        conditional = "if"
                        input_value = "/"
                    },
                ]
            },
        ]
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
        azion_edge_application_origin.default,
    ]
}

resource "azion_edge_application_rule_engine" "redirect_to_https" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id

    results = {
        name        = "redirect_to_https"
        phase       = "request"
        description = "Redirect to the same URL on HTTPS protocol, issuing a 301 response code (Moved Permanently). You may change the response code to 302 if needed."
        behaviors = [
            {
                name = "redirect_http_to_https"
                target_object = {
                    target = "https://$${host}/$${uri}?$${args}"
                }
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${scheme}"
                        operator    = "is_equal"
                        conditional = "if"
                        input_value = "http"
                    },
                ]
            },
        ]
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
    ]
}

resource "azion_edge_application_rule_engine" "www_blog_itau_com_br" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id

    results = {
        name        = "www_blog_itau_com_br"
        phase       = "request"
        description = ""
        behaviors = [
            {
                name = "redirect_to_301"
                target_object = {
                    target = "https://blog.itau.com.br/$${uri}?$${args}"
                }
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${host}"
                        operator    = "matches"
                        conditional = "if"
                        input_value = "\^(www\\.blog\\.itau\\.com\\.br)(\\?.*)?$"
                    },
                ]
            },
        ]
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
    ]
}

resource "azion_edge_application_rule_engine" "offload_origin" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id

    results = {
        name        = "offload_origin"
        phase       = "request"
        description = "Control the settings related to caching content at the edge and in the browser. As a result, fewer requests go to your origin, fewer bytes leave your data centers, and your assets are closer to your users."
        behaviors = [
            {
                name = "bypass_cache_phase"
                target_object = {}
            },
            {
                name = "set_cache_policy"
                target_object = {
                    target = azion_edge_application_cache_setting.offload_origin.id
                }
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${uri}"
                        operator    = "starts_with"
                        conditional = "if"
                        input_value = "/"
                    },
                ]
            },
        ]
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
        azion_edge_application_cache_setting.offload_origin,
    ]
}

resource "azion_edge_application_rule_engine" "offload_origin_filter_response_header" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id

    results = {
        name        = "offload_origin_filter_response_header"
        phase       = "response"
        description = "Control the settings related to caching content at the edge and in the browser. As a result, fewer requests go to your origin, fewer bytes leave your data centers, and your assets are closer to your users."
        behaviors = [
            {
                name = "filter_response_header"
                target_object = {
                    target = "Vary"
                }
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${request_uri}"
                        operator    = "starts_with"
                        conditional = "if"
                        input_value = "/"
                    },
                ]
            },
        ]
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
        azion_edge_application_cache_setting.offload_origin,
    ]
}

resource "azion_edge_application_rule_engine" "css_and_javascript" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id

    results = {
        name        = "css_and_javascript"
        phase       = "request"
        description = "Override the default caching behavior for CSS and JavaScript"
        behaviors = [
            {
                name = "set_cache_policy"
                target_object = {
                    target = azion_edge_application_cache_setting.css_and_javascript.id
                }
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${request_uri}}"
                        operator    = "matches"
                        conditional = "if"
                        input_value = "\\.(css|js)(\\?.*)?$"
                    },
                ]
            },
        ]
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
        azion_edge_application_cache_setting.css_and_javascript,
    ]
}

resource "azion_edge_application_rule_engine" "fonts" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id

    results = {
        name        = "fonts"
        phase       = "request"
        description = "Override the default caching behavior for fonts."
        behaviors = [
            {
                name = "set_cache_policy"
                target_object = {
                    target = azion_edge_application_cache_setting.fonts.id
                }
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${request_uri}}"
                        operator    = "matches"
                        conditional = "if"
                        input_value = "\\.(eot|woff|woff2|otf|ttf)(\\?.*)?$"
                    },
                ]
            },
        ]
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
        azion_edge_application_cache_setting.fonts,
    ]
}

resource "azion_edge_application_rule_engine" "images" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id

    results = {
        name        = "images"
        phase       = "request"
        description = "Override the default caching behavior for images."
        behaviors = [
            {
                name = "set_cache_policy"
                target_object = {
                    target = azion_edge_application_cache_setting.images.id
                }
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${request_uri}}"
                        operator    = "matches"
                        conditional = "if"
                        input_value = "\\.(jpg|jpeg|png|gif|webp|jp2|ico|svg|svgz)(\\?.*)?$"
                    },
                ]
            },
        ]
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
        azion_edge_application_cache_setting.images,
    ]
}

resource "azion_edge_application_rule_engine" "files" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id

    results = {
        name        = "files"
        phase       = "request"
        description = "Override the default caching behavior for files. Files containing Personal Identified Information (PII) should require Edge authentication or not be cached at all."
        behaviors = [
            {
                name = "set_cache_policy"
                target_object = {
                    target = azion_edge_application_cache_setting.files.id
                }
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${request_uri}}"
                        operator    = "matches"
                        conditional = "if"
                        input_value = "\\.(pdf|doc|docx|odt)(\\?.*)?$"
                    },
                ]
            },
        ]
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
        azion_edge_application_cache_setting.files,
    ]
}

resource "azion_edge_application_rule_engine" "other_static_objects" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id

    results = {
        name        = "other_static_objects"
        phase       = "request"
        description = "Override the default caching behavior for other static objects."
        behaviors = [
            {
                name = "set_cache_policy"
                target_object = {
                    target = azion_edge_application_cache_setting.other_static_objects.id
                }
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${request_uri}}"
                        operator    = "matches"
                        conditional = "if"
                        input_value = "\\.(aif|aiff|au|avi|bin|bmp|cab|carb|cct|cdf|class|dcr|dtd|exe|flv|gcf|gff|grv|hdml|hqx|ini|mov|mp3|nc|pct|ppc|pws|swa|swf|txt|vbs|w32|wav|midi|wbmp|wml|wmlc|wmls|wmlsc|xsd|zip|pict|tif|tiff|mid|jxr|jar)(\\?.*)?$"
                    },
                ]
            },
        ]
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
        azion_edge_application_cache_setting.other_static_objects,
    ]
}

resource "azion_edge_application_rule_engine" "html_pages" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id

    results = {
        name        = "html_pages"
        phase       = "request"
        description = "Override the default caching behavior for HTML pages cached on edge servers."
        behaviors = [
            {
                name = "bypass_cache_phase"
                target_object = {}
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${request_uri}}"
                        operator    = "matches"
                        conditional = "if"
                        input_value = "\\.(html|htm|php|jsp|aspx|EMPTY_STRING)(\\?.*)?$"
                    },
                ]
            },
        ]
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
    ]
}

resource "azion_edge_application_rule_engine" "redirect_artigos_home" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id

    results = {
        name        = "redirect_artigos_home"
        phase       = "request"
        description = ""
        behaviors = [
            {
                name = "redirect_to_301"
                target_object = {
                    target = "$${scheme}://blog.itau.com.br/"
                }
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${uri}"
                        operator    = "matches"
                        conditional = "if"
                        input_value = "(\\/artigos|\\/artigos\\/)"
                    },
                ]
            },
        ]
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
    ]
}

resource "azion_edge_application_rule_engine" "obfuscate_backend_info_filter_response_header" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id

    results = {
        name        = "obfuscate_backend_info_filter_response_header"
        phase       = "response"
        description = "Do not expose back-end information unless the request contains an additional secret header. Regularly change the criteria to use a specific unique value for the secret header."
        behaviors = [
            {
                name = "filter_response_header"
                target_object = {
                    target = "X-Powered-By"
                }
            },
            {
                name = "filter_response_header"
                target_object = {
                    target = "Server"
                }
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${http_x_akamai_debug}"
                        operator    = "is_not_equal"
                        conditional = "if"
                        input_value = "true"
                    },
                ]
            },
        ]
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
    ]
}

resource "azion_edge_application_rule_engine" "compressible_objects_enable_gzip" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id

    results = {
        name        = "compressible_objects_enable_gzip"
        phase       = "response"
        description = "Serve gzip compressed content for text-based formats."
        behaviors = [
            {
                name = "enable_gzip"
                target_object = {}
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${request_uri}"
                        operator    = "starts_with"
                        conditional = "if"
                        input_value = "/"
                    },
                ]
            },
        ]
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
    ]
}

resource "azion_edge_application_rule_engine" "martechcmsless" {
    edge_application_id = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id

    results = {
        name        = "martechcmsless"
        phase       = "request"
        description = ""
        behaviors = [
            {
                name = "set_origin"
                target_object = {
                    target = azion_edge_application_origin.martechcmsless.id
                }
            },
            {
                name = "enable_gzip"
                target_object = {}
            },
            {
                name = "add_request_header"
                target_object = {
                    target = "True-Client-IP: $${remote_addr}"
                }
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${uri}"
                        operator    = "starts_with"
                        conditional = "if"
                        input_value = "/"
                    },
                ]
            },
        ]
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
        azion_edge_application_origin.martechcmsless,
    ]
}

resource "azion_domain" "blog_itau_com_br" {
    domain = {
        cnames                    = ["blog.itau.com.br", "www.blog.itau.com.br"]
        name                      = "blog.itau.com.br"
        digital_certificate_id    = null
        cname_access_only         = false
        edge_application_id       = azion_edge_application_main_setting.blog_itau_com_br.edge_application.application_id
        is_active                 = true
    }
    depends_on = [
        azion_edge_application_main_setting.blog_itau_com_br,
    ]
}

