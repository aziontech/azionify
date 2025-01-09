variable "azion_api_token" {
    default     = null
    description = "Azion API token"
}

provider "azion" {
    api_token = "8182f95468d8350f8aac9b702ce6f539ce241e37"
}

resource "azion_edge_application_main_setting" "www_hipercard_com_br" {
    edge_application = {
        name                     = "www.hipercard.com.br"
        supported_ciphers        = "TLSv1.2_2021"
        delivery_protocol        = "http,https"
        http_port                = [80]
        https_port               = [443]
        minimum_tls_version      = "tls_1_2"
        debug_rules              = false
        caching                  = true
        edge_firewall            = false
        edge_functions           = true
        image_optimization       = false
        http3                    = false
        application_acceleration = true
        l2_caching               = false
        load_balancer            = false
        raw_logs                 = false
        device_detection         = false
        web_application_firewall = false
    }
}

resource "azion_edge_application_origin" "default" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id
    origin = {
        name        = "default"
        origin_type = "single_origin"
        addresses = [
            { "address" : "hipercard.cloud.itau.com.br" },
        ],
        origin_protocol_policy = "preserve"
        host_header = "hipercard.cloud.itau.com.br"
        origin_path = ""
        connection_timeout = 60
        timeout_between_bytes = 120
        hmac_authentication = false
        hmac_region_name = ""
        hmac_access_key = ""
        hmac_secret_key = ""
    }
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br]
}

resource "azion_edge_application_origin" "arquivos_est_ticos" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id
    origin = {
        name        = "arquivos_est_ticos"
        origin_type = "single_origin"
        addresses = [
            { "address" : "hipercard.cloud.itau.com.br" },
        ],
        origin_protocol_policy = "preserve"
        host_header = "hipercard.cloud.itau.com.br"
        origin_path = "/"
        connection_timeout = 60
        timeout_between_bytes = 120
        hmac_authentication = false
        hmac_region_name = ""
        hmac_access_key = ""
        hmac_secret_key = ""
    }
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br]
}

resource "azion_edge_application_origin" "hipercard_hipercard_cloud_itau_com_br" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id
    origin = {
        name        = "hipercard_hipercard_cloud_itau_com_br"
        origin_type = "single_origin"
        addresses = [
            { "address" : "hipercard.cloud.itau.com.br" },
        ],
        origin_protocol_policy = "preserve"
        host_header = "hipercard.cloud.itau.com.br"
        origin_path = ""
        connection_timeout = 60
        timeout_between_bytes = 120
        hmac_authentication = false
        hmac_region_name = ""
        hmac_access_key = ""
        hmac_secret_key = ""
    }
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br]
}

resource "azion_edge_application_cache_setting" "default" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id
    cache_settings = {
        name = "default"
        browser_cache_settings = "honor"
        browser_cache_settings_maximum_ttl = 0
        cdn_cache_settings = "override"
        cdn_cache_settings_maximum_ttl = 3600
        adaptive_delivery_action = "ignore"
        cache_by_query_string = "ignore"
        cache_by_cookies = "ignore"
        enable_stale_cache = false
    }
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br]
}

resource "azion_edge_application_cache_setting" "static_content" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id
    cache_settings = {
        name = "static_content"
        browser_cache_settings = "honor"
        browser_cache_settings_maximum_ttl = 0
        cdn_cache_settings = "override"
        cdn_cache_settings_maximum_ttl = 31536000
        adaptive_delivery_action = "ignore"
        cache_by_query_string = "ignore"
        cache_by_cookies = "ignore"
        enable_stale_cache = false
    }
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br]
}

resource "azion_edge_application_cache_setting" "image_and_video_manager_images" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id
    cache_settings = {
        name = "image_and_video_manager_images"
        browser_cache_settings = "honor"
        browser_cache_settings_maximum_ttl = 0
        cdn_cache_settings = "override"
        cdn_cache_settings_maximum_ttl = 2592000
        adaptive_delivery_action = "ignore"
        cache_by_query_string = "ignore"
        cache_by_cookies = "ignore"
        enable_stale_cache = false
    }
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br]
}

resource "azion_edge_application_rule_engine" "default" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id

    results = {
        name        = "default"
        phase       = "default"
        description = ""
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
                    target = "true-Client-IP: $${remote_addr}"
                }
            },
            {
                name = "set_cache_policy"
                target_object = {
                    target = azion_edge_application_cache_setting.default.id
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
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br, azion_edge_application_origin.default, azion_edge_application_cache_setting.default]
}

resource "azion_edge_application_rule_engine" "default_filter_request_header" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id

    results = {
        name        = "filter_request_header"
        phase       = "response"
        description = ""
        behaviors = [
            {
                name = "filter_request_header"
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
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br, azion_edge_application_origin.default, azion_edge_application_cache_setting.default]
}

resource "azion_edge_application_rule_engine" "redirect_to_https" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id

    results = {
        name        = "redirect_to_https"
        phase       = "request"
        description = "Redirect to the same URL on HTTPS protocol, issuing a 301 response code (Moved Permanently). You may change the response code to 302 if needed."
        behaviors = [
            {
                name = "redirect_http_to_https"
                target_object = {
                    target = "$${scheme}://$${{host}}/$${request_uri}"
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
                        input_value = "*"
                    },
                ]
            },
        ]
    }
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br]
}

resource "azion_edge_application_rule_engine" "content_compression_enable_gzip" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id

    results = {
        name        = "enable_gzip"
        phase       = "response"
        description = ""
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
                        variable    = "$${http_content_type}"
                        operator    = "matches"
                        conditional = "if"
                        input_value = "(text\\/html*|text\\/css*|application\\/x-javascript*|application\\/javascript|application\\/x-javascript|application\\/json|application\\/x-json|application\\/*+json|application\\/*+xml|application\\/text|application\\/vnd\\.microsoft\\.icon|application\\/vnd-ms-fontobject|application\\/x-font-ttf|application\\/x-font-opentype|application\\/x-font-truetype|application\\/xmlfont\\/eot|application\\/xml|font\\/opentype|font\\/otf|font\\/eot|image\\/svg+xml|image\\/vnd\\.microsoft\\.icon)"
                    },
                ]
            },
        ]
    }
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br]
}

resource "azion_edge_application_rule_engine" "static_content" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id

    results = {
        name        = "static_content"
        phase       = "request"
        description = ""
        behaviors = [
            {
                name = "set_cache_policy"
                target_object = {
                    target = azion_edge_application_cache_setting.static_content.id
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
                        input_value = "\\.(aif|aiff|au|avi|bin|bmp|cab|carb|cct|cdf|class|css|doc|dcr|dtd|exe|flv|gcf|gff|gif|grv|hdml|hqx|ico|ini|jpeg|jpg|js|mov|mp3|nc|pct|pdf|png|ppc|pws|swa|swf|txt|vbs|w32|wav|wbmp|wml|wmlc|wmls|wmlsc|xsd|zip|woff|woff2|svg)(\\?.*)?$"
                    },
                ]
            },
        ]
    }
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br, azion_edge_application_cache_setting.static_content]
}

resource "azion_edge_application_rule_engine" "browser_caching" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id

    results = {
        name        = "browser_caching"
        phase       = "request"
        description = ""
        behaviors = [
            {
                name = "set_cache_policy"
                target_object = {
                    target = azion_edge_application_cache_setting.static_content.id
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
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br, azion_edge_application_cache_setting.static_content]
}

resource "azion_edge_application_rule_engine" "redirect_top_level" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id

    results = {
        name        = "redirect_top_level"
        phase       = "request"
        description = ""
        behaviors = [
            {
                name = "redirect_to_301"
                target_object = {
                    target = "$${scheme}://www.hipercard.com.br/$${request_uri}"
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
                        input_value = "hipercard.com.br"
                    },
                ]
            },
        ]
    }
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br]
}

resource "azion_edge_application_rule_engine" "html_to_ending" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id

    results = {
        name        = "html_to_ending"
        phase       = "request"
        description = ""
        behaviors = [
            {
                name = "capture_match_groups"
                target_object = {
                    captured_array = "PMUSER_RED"
                    subject = "$${uri}"
                    regex = "(.*)\\/index\\.html"
                }
            },
            {
                name = "redirect_to_301"
                target_object = {
                    target = "$${scheme}://www.hipercard.com.br/$${request_uri}"
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
                        input_value = "(\\/cartoes\\/index.html|\\/cartoes\\/ajuda\\/index.html)"
                    },
                ]
            },
        ]
    }
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br]
}

resource "azion_edge_application_rule_engine" "image_and_video_manager_images" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id

    results = {
        name        = "image_and_video_manager_images"
        phase       = "request"
        description = "Apply the Image and Video Manager (Images) behavior here as you would normally."
        behaviors = [
            {
                name = "set_cache_policy"
                target_object = {
                    target = azion_edge_application_cache_setting.image_and_video_manager_images.id
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
                        input_value = "\\.(jpg|gif|jpeg|png|imviewer)(\\?.*)?$"
                    },
                ]
            },
        ]
    }
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br, azion_edge_application_cache_setting.image_and_video_manager_images]
}

resource "azion_edge_application_rule_engine" "arquivos_est_ticos" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id

    results = {
        name        = "arquivos_est_ticos"
        phase       = "request"
        description = ""
        behaviors = [
            {
                name = "set_origin"
                target_object = {
                    target = azion_edge_application_origin.arquivos_est_ticos.id
                }
            },
            {
                name = "enable_gzip"
                target_object = {}
            },
            {
                name = "add_request_header"
                target_object = {
                    target = "true-Client-IP: $${remote_addr}"
                }
            },
            {
                name = "rewrite_request"
                target_object = {
                    target = "$${uri}"
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
                        input_value = "(\\/assets\\/*)"
                    },
                ]
            },
        ]
    }
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br, azion_edge_application_origin.arquivos_est_ticos]
}

resource "azion_edge_application_rule_engine" "demais_p_ginas_hipercard" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id

    results = {
        name        = "demais_p_ginas_hipercard"
        phase       = "request"
        description = "todas as demais paginas de hipercard caem nessa rota, exemplo /cartoes /bandeira "
        behaviors = [
            {
                name = "rewrite_request"
                target_object = {
                    target = "$${uri}/index.html"
                }
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${uri}"
                        operator    = "does_not_match"
                        conditional = "if"
                        input_value = "(\\/|\\/assets\\/*)"
                    },
                ]
            },
        ]
    }
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br]
}

resource "azion_edge_application_rule_engine" "hipercard_hipercard_cloud_itau_com_br" {
    edge_application_id = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id

    results = {
        name        = "hipercard_hipercard_cloud_itau_com_br"
        phase       = "request"
        description = ""
        behaviors = [
            {
                name = "set_origin"
                target_object = {
                    target = azion_edge_application_origin.hipercard_hipercard_cloud_itau_com_br.id
                }
            },
            {
                name = "enable_gzip"
                target_object = {}
            },
        ]
        criteria = [
            {
                entries = [
                    {
                        variable    = "$${uri}"
                        operator    = "is_equal"
                        conditional = "if"
                        input_value = "*"
                    },
                ]
            },
        ]
    }
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br, azion_edge_application_origin.hipercard_hipercard_cloud_itau_com_br]
}

resource "azion_domain" "www_hipercard_com_br" {
    domain = {
        cnames                    = [""]
        name                      = "www.hipercard.com.br"
        digital_certificate_id    = null
        cname_access_only         = false
        edge_application_id       = azion_edge_application_main_setting.www_hipercard_com_br.edge_application.application_id
        is_active                 = true
    }
    depends_on = [azion_edge_application_main_setting.www_hipercard_com_br]
}

