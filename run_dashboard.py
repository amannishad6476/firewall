"""
AI Agent Firewall - Streamlit Dashboard Server with Subpath Route Compatibility.

Prevents 404 Not Found errors on `/{subpage}/_stcore/host-config` and
`/{subpage}/_stcore/health` when navigating between multipage routes in Streamlit.
"""

import sys
from starlette.routing import Route
import streamlit.web.server.starlette.starlette_routes as sr
import streamlit.web.server.starlette.starlette_app as sa

# 1. Patch create_host_config_routes to also serve /{subpage}/_stcore/host-config
_orig_host_config_routes = sr.create_host_config_routes

def _patched_host_config_routes(base_url: str):
    routes = _orig_host_config_routes(base_url)
    if routes:
        endpoint = routes[0].endpoint
        sub_route = Route(
            "/{subpage:path}/_stcore/host-config",
            endpoint,
            methods=["GET", "HEAD"]
        )
        routes.append(sub_route)
    return routes

sr.create_host_config_routes = _patched_host_config_routes
sa.create_host_config_routes = _patched_host_config_routes

# 2. Patch create_health_routes to also serve /{subpage}/_stcore/health
_orig_health_routes = sr.create_health_routes

def _patched_health_routes(runtime, base_url: str):
    routes = _orig_health_routes(runtime, base_url)
    if len(routes) >= 2:
        endpoint_get = routes[0].endpoint
        endpoint_opt = routes[1].endpoint
        routes.append(Route("/{subpage:path}/_stcore/health", endpoint_get, methods=["GET", "HEAD"]))
        routes.append(Route("/{subpage:path}/_stcore/health", endpoint_opt, methods=["OPTIONS"]))
    elif routes:
        routes.append(Route("/{subpage:path}/_stcore/health", routes[0].endpoint, methods=["GET", "HEAD"]))
    return routes

sr.create_health_routes = _patched_health_routes
sa.create_health_routes = _patched_health_routes

if __name__ == "__main__":
    from streamlit.web.bootstrap import run
    
    script_path = "dashboard/app.py"
    # Pass along any additional args if needed
    run(script_path, False, sys.argv[1:], {})
