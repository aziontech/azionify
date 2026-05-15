# Architecture — Azionify

## Overview

A Python CLI tool that converts Terraform configurations from other CDN providers (currently Akamai) into Azion-compatible Terraform resources. Parses HCL2 input, maps provider-specific behaviors/criteria to Azion equivalents, and generates ready-to-apply Terraform files.

## Conversion Pipeline

```
Akamai Terraform File (.tf)
  ↓
reader.py — HCL2 parsing (python-hcl2)
  ↓
akamai.py — Orchestrator
  ├─ Extract hostnames, origins, main settings
  └─ Process each akamai_property resource
      ↓
converter.py — Core engine
  ├─ create_main_resources()
  │   ├─ converter_main_settings.py → azion_edge_application_main_setting
  │   ├─ converter_domain.py → azion_domain
  │   └─ converter_origin.py → azion_edge_application_origin
  └─ process_rules() — recursive rule tree traversal
      ├─ converter_cache_settings.py → azion_edge_application_cache_setting
      ├─ converter_rules_engine.py → azion_edge_application_rule_engine
      ├─ converter_waf.py → azion_waf_rule_set
      ├─ converter_edge_function.py → azion_edge_function
      ├─ converter_edge_function_instance.py → azion_edge_application_edge_functions_instance
      └─ converter_digital_certificate.py → azion_digital_certificate
  ↓
writer.py — Terraform output generation
  ↓
Azion Terraform File (.tf)
```

## Components

| Module | Path | Purpose |
|--------|------|---------|
| CLI entry | `src/main.py` | Argument parsing, provider dispatch |
| Reader | `src/reader.py` | HCL2 file parsing, function map loading |
| Writer | `src/writer.py` | Terraform output file generation |
| Resources | `src/azion_resources.py` | Resource container with query methods |
| Utilities | `src/utils.py` | Name sanitization, TTL parsing, JSON handling |
| Akamai orchestrator | `src/akamai/akamai.py` | Akamai-specific conversion entry point |
| Core converter | `src/akamai/converter.py` | Resource processing engine, rule traversal |
| Main settings | `src/akamai/converter_main_settings.py` | Edge application config conversion |
| Domain | `src/akamai/converter_domain.py` | CNAME/hostname conversion |
| Origin | `src/akamai/converter_origin.py` | Backend/origin server conversion |
| Cache | `src/akamai/converter_cache_settings.py` | Cache policy/TTL conversion |
| Rules engine | `src/akamai/converter_rules_engine.py` | Criteria/behavior rule conversion |
| WAF | `src/akamai/converter_waf.py` | WAF rule set conversion |
| Edge function | `src/akamai/converter_edge_function.py` | Edge function definitions |
| Function instance | `src/akamai/converter_edge_function_instance.py` | Function binding to apps |
| Certificate | `src/akamai/converter_digital_certificate.py` | SSL certificate conversion |
| Mappings | `src/akamai/mapping.py` | Akamai↔Azion behavior/criteria maps |
| Akamai utils | `src/akamai/utils.py` | Variable mapping, operator conversion |

## Azion Resources Generated

| Terraform Resource | From Akamai | Purpose |
|-------------------|-------------|---------|
| `azion_edge_application_main_setting` | Property | Core app configuration |
| `azion_edge_application_origin` | Origin behaviors | Backend server definitions |
| `azion_domain` | Hostnames | Domain/CNAME bindings |
| `azion_edge_application_cache_setting` | Caching behaviors | Cache policies and TTLs |
| `azion_edge_application_rule_engine` | Rules + criteria | Request/response processing rules |
| `azion_waf_rule_set` | WAF behaviors | Firewall rule configuration |
| `azion_edge_function` | Custom functions | Edge function code |
| `azion_edge_application_edge_functions_instance` | Function refs | Function binding to application |
| `azion_digital_certificate` | CPS certificates | SSL/TLS certificate mapping |

## Key Mapping Systems

### Variable Mapping (Akamai → Azion)
- `AK_PATH` → `$${uri}`
- `AK_CLIENT_IP` → `$${remote_addr}`
- `AK_HOST` → `$${host}`
- `AK_SCHEME` → `$${scheme}`
- `AK_QUERY` → `$${args}`
- `AK_METHOD` → `$${request_method}`

### Operator Mapping
- `EQUALS` / `EQUALS_ONE_OF` → `is_equal`
- `MATCHES` / `MATCHES_ONE_OF` → `matches`
- `STARTS_WITH` → `starts_with`
- `EXISTS` / `DOES_NOT_EXIST` → `exists` / `does_not_exist`

### Conditional Logic
- `all` → `and`, `any` → `or`, `one` → `if`

## Technology Stack

- **Language**: Python 3.8–3.12
- **HCL Parsing**: python-hcl2 7.3
- **Expression Parsing**: lark 1.3
- **Linting**: pylint
- **License**: MIT

## Design Decisions

- **Modular converters**: Each Azion resource type has its own converter module for maintainability
- **Class-level resource storage**: `AzionResource` stores all resources in a class-level list for cross-converter queries
- **Automatic dependency tracking**: `depends_on` fields generated based on resource relationships
- **Environment-aware naming**: Resource names get environment suffixes for non-production targets
- **Extensible provider pattern**: New CDN providers (CloudFront, Fastly) can be added by implementing a new converter package
