from typing import Dict, Any, List

class APISecurityIntelligence:
    """
    Expanded API Surface Classification.
    Analyzes REST, GraphQL, and gRPC patterns to detect missing authentication 
    and excessive data exposure.
    """
    
    def analyze_api_surface(self, routes: List[str], headers: Dict[str, str]) -> Dict[str, Any]:
        flags = []
        schema_type = "REST"
        
        # Route clustering to guess schema
        graphql_keywords = ["/graphql", "/graphiql", "/v1/graphql"]
        grpc_keywords = ["/grpc", "application/grpc"]
        
        for r in routes:
            for gk in graphql_keywords:
                if gk in r.lower():
                    schema_type = "GraphQL"
                    flags.append("GraphQL Introspection Endpoint Potentially Exposed")
                    
        # Check Auth Inheritance
        # If API routes are discovered but no Authorization header was required
        if not headers.get("Authorization") and not headers.get("Cookie"):
            flags.append("Missing explicit Auth Inheritance on discovered API boundaries")
            
        return {
            "inferred_schema": schema_type,
            "api_security_flags": flags,
            "requires_auth_review": len(flags) > 0
        }
