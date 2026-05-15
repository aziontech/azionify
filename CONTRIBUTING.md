# Contributing to Azionify

## Overview

CLI tool that converts Terraform configurations from other CDN providers (currently Akamai) into Azion-compatible Terraform resources.

## Prerequisites

- Python 3.8+
- pip

## Repository Structure

```
src/
  main.py                           # CLI entry point
  reader.py                         # HCL2 file parsing
  writer.py                         # Terraform output generation
  azion_resources.py                # Resource container with queries
  utils.py                          # Shared utilities
  akamai/
    akamai.py                       # Akamai conversion orchestrator
    converter.py                    # Core resource processing engine
    converter_main_settings.py      # Edge application config
    converter_domain.py             # Domain/CNAME conversion
    converter_origin.py             # Origin/backend conversion
    converter_cache_settings.py     # Cache policy conversion
    converter_rules_engine.py       # Rules engine conversion
    converter_waf.py                # WAF rule conversion
    converter_edge_function.py      # Edge function definitions
    converter_edge_function_instance.py  # Function instantiation
    converter_digital_certificate.py     # Certificate conversion
    mapping.py                      # Behavior/criteria mappings
    utils.py                        # Akamai-specific utilities
```

## Development Workflow

1. Create a branch from `main`
2. Install dependencies: `pip install -r requirements.txt`
3. Make changes
4. Run linting: `pylint --disable=C,R,E0401,W0107,W0613,W0612,W0221,W1203 $(git ls-files '*.py')`
5. Test with a sample Akamai Terraform file
6. Open a PR

## Adding a New Converter Module

1. Create `src/akamai/converter_<resource_type>.py`
2. Implement the `create_<resource>()` function that returns a resource dict
3. Register the converter call in `src/akamai/converter.py` (in `process_rules()` or `create_main_resources()`)
4. Add the resource type to the writer in `src/writer.py`

## Adding Akamai Behavior Mappings

Edit `src/akamai/mapping.py` to add new behavior-to-Azion mappings. Follow the existing pattern of lambda functions for dynamic value transformation.

## Code Style

- pylint for linting (Python 3.8+ compatibility)
- Use logging (INFO/DEBUG/WARNING/ERROR) instead of print statements
- Sanitize all resource names via `utils.sanitize_name()`

## Code Review

- All PRs require approval from `@aziontech/team-data-routing`
- Security config changes require `@aziontech/security-office` review
