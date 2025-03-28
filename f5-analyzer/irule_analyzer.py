import re

def analyze_irule(irule_content):
    """
    Analyzes an iRule and determines compatibility with F5 Distributed Cloud service policies.
    Returns mappable features, alternatives needed, and unsupported features.
    """
    analysis = {
        "mappable": [],        # Can be directly mapped to service policies
        "alternatives": [],     # Requires alternative implementation
        "unsupported": [],     # Currently not possible in XC
        "warnings": [],         # Additional considerations
        "events": {}           # Track which events contain which features
    }
    
    # Extract all event blocks first
    events = extract_all_events(irule_content)
    analysis["events"] = events
    
    # Check for session tracking
    if re.search(r'CLIENT_ACCEPTED.*?IP::client_addr', irule_content, re.DOTALL):
        analysis["mappable"].append({
            "feature": "Client IP tracking",
            "service_policy": "Client IP match conditions in service policy",
            "event": "CLIENT_ACCEPTED"
        })
    
    # Check for table operations
    if re.search(r'table\s+(set|lookup|delete)', irule_content):
        analysis["alternatives"].append({
            "feature": "Table operations for state management",
            "alternative": "Consider using distributed key-value store or custom metadata",
            "event": "GLOBAL"
        })
    
    # Check for pattern matching and redirects
    if re.search(r'regexp|string\s+match', irule_content):
        analysis["mappable"].append({
            "feature": "Pattern matching",
            "service_policy": "Regular expression matching in service policy rules",
            "event": "GLOBAL"
        })
    
    if re.search(r'HTTP::redirect', irule_content):
        analysis["mappable"].append({
            "feature": "HTTP redirects",
            "service_policy": "HTTP redirect actions in service policy",
            "event": "HTTP_REQUEST"
        })
    
    # Check for data collection
    if re.search(r'HTTP::collect', irule_content):
        analysis["alternatives"].append({
            "feature": "Request/Response data collection",
            "alternative": "Consider using WAF policies or custom rules for payload inspection",
            "event": "HTTP_REQUEST_DATA"
        })
    
    # Check for header manipulation
    if re.search(r'HTTP::header\s+(insert|remove)', irule_content):
        analysis["mappable"].append({
            "feature": "Header manipulation",
            "service_policy": "Request/Response header actions in service policy",
            "event": "HTTP_REQUEST"
        })
    
    # Check for response handling
    if 'HTTP_RESPONSE' in irule_content:
        analysis["mappable"].append({
            "feature": "Response processing",
            "service_policy": "Response phase actions in service policy",
            "event": "HTTP_RESPONSE"
        })
    
    # Check for complex flow control
    if re.search(r'(if|switch|foreach|while)', irule_content):
        analysis["warnings"].append({
            "feature": "Complex flow control",
            "note": "May require multiple service policy rules and careful logic restructuring",
            "event": "GLOBAL"
        })
    
    # Check for static variable initialization
    if re.search(r'set\s+static::', irule_content):
        analysis["alternatives"].append({
            "feature": "Static variable initialization",
            "alternative": "Consider using system metadata or configuration",
            "event": "RULE_INIT"
        })
    
    # Check for memory/buffer management
    if re.search(r'string\s+range|string\s+length', irule_content):
        analysis["warnings"].append({
            "feature": "Memory/buffer management",
            "note": "Consider request/response size limits in Load Balancer configuration",
            "event": "GLOBAL"
        })
    
    # Check for TCP/IP level operations
    if re.search(r'TCP::|IP::', irule_content):
        analysis["alternatives"].append({
            "feature": "TCP/IP level operations",
            "alternative": "Use Load Balancer TCP/UDP settings and service policies where applicable",
            "event": "CLIENT_ACCEPTED"
        })
    
    # Check for error handling
    if re.search(r'catch\s*{', irule_content):
        analysis["warnings"].append({
            "feature": "TCL error handling",
            "note": "Implement appropriate error handling in service policies and monitoring",
            "event": "GLOBAL"
        })
    
    # Check for logging
    if re.search(r'log\s+local', irule_content):
        analysis["alternatives"].append({
            "feature": "Local logging",
            "alternative": "Configure appropriate logging in XC monitoring and alerts",
            "event": "GLOBAL"
        })
    
    # Check for WebSocket handling
    if 'HTTP::is_websocket' in irule_content or 'WebSocket' in irule_content:
        analysis["mappable"].append({
            "feature": "WebSocket Support",
            "service_policy": "WebSocket configuration in Load Balancer",
            "notes": "Native WebSocket support with proper configuration",
            "event": "HTTP_REQUEST"
        })
    
    # Check for HTTP/2 specific features
    if re.search(r'HTTP2::', irule_content):
        analysis["warnings"].append({
            "feature": "HTTP/2 Specific Features",
            "note": "Some HTTP/2 features may need reconfiguration in XC",
            "recommendation": "Configure HTTP/2 settings in Load Balancer configuration",
            "event": "HTTP_REQUEST"
        })
    
    # Check for SSL/TLS specific operations
    if re.search(r'SSL::|X509::', irule_content):
        analysis["mappable"].append({
            "feature": "SSL/TLS Operations",
            "service_policy": "Available through Load Balancer SSL/TLS settings",
            "notes": "Configure SSL/TLS settings at LB level",
            "event": "CLIENTSSL_HANDSHAKE"
        })
    
    # Check for specific event handlers
    events = {
        'HTTP_REQUEST': check_http_request_capabilities,
        'HTTP_RESPONSE': check_http_response_capabilities,
        'CLIENT_ACCEPTED': check_client_accepted_capabilities,
        'SERVER_CONNECTED': check_server_connected_capabilities,
        'RULE_INIT': check_rule_init_capabilities,
        'HTTP_REQUEST_DATA': check_http_request_data_capabilities,
        'HTTP_RESPONSE_DATA': check_http_response_data_capabilities,
        'CLIENTSSL_HANDSHAKE': check_clientssl_handshake_capabilities,
        'CLIENTSSL_CLIENTCERT': check_clientssl_clientcert_capabilities
    }
    
    for event, checker in events.items():
        if re.search(rf'when\s+{event}\s*{{', irule_content, re.IGNORECASE):
            event_content = extract_event_content(irule_content, event)
            if event_content:
                checker(event_content, analysis)
    
    return analysis

def extract_all_events(irule_content):
    """Extract all event blocks from the iRule"""
    events = {}
    event_pattern = r'when\s+(\w+)\s*{([^}]+)}'
    matches = re.finditer(event_pattern, irule_content, re.DOTALL)
    
    for match in matches:
        event_name = match.group(1)
        event_content = match.group(2).strip()
        events[event_name] = event_content
    
    return events

def extract_event_content(irule_content, event):
    """Extract the content within a specific event block"""
    pattern = rf'when\s+{event}\s*{{(.*?)}}'
    matches = re.finditer(pattern, irule_content, re.DOTALL)
    contents = []
    for match in matches:
        contents.append(match.group(1))
    return '\n'.join(contents) if contents else None

def check_http_request_capabilities(content, analysis):
    """Analyze HTTP_REQUEST event content"""
    
    # URI manipulation
    if re.search(r'HTTP::uri', content):
        analysis["mappable"].append({
            "feature": "URI manipulation",
            "service_policy": "HTTP URI Path Matcher in service policy rules",
            "event": "HTTP_REQUEST"
        })
    
    # Query parameter handling
    if re.search(r'HTTP::query', content):
        analysis["mappable"].append({
            "feature": "Query parameter processing",
            "service_policy": "Query parameter matching in service policy",
            "event": "HTTP_REQUEST"
        })
    
    # Custom content routing
    if re.search(r'pool\s+\S+', content):
        analysis["alternatives"].append({
            "feature": "Custom content routing",
            "alternative": "Use Load Balancer rules and origin pools",
            "event": "HTTP_REQUEST"
        })
    
    # Path manipulation
    if re.search(r'HTTP::path', content):
        analysis["mappable"].append({
            "feature": "Path manipulation",
            "service_policy": "L7 Route path rewrite rules",
            "event": "HTTP_REQUEST"
        })
    
    # Host header manipulation
    if re.search(r'HTTP::host', content):
        analysis["mappable"].append({
            "feature": "Host header rewriting",
            "service_policy": "L7 Route configuration",
            "notes": "Configure in route settings",
            "event": "HTTP_REQUEST"
        })

def check_http_request_data_capabilities(content, analysis):
    """Analyze HTTP_REQUEST_DATA event content"""
    if re.search(r'HTTP::payload', content):
        analysis["alternatives"].append({
            "feature": "Request payload inspection",
            "alternative": "Use WAF policies or custom security rules",
            "event": "HTTP_REQUEST_DATA"
        })

def check_http_response_capabilities(content, analysis):
    """Analyze HTTP_RESPONSE event content"""
    
    # Response header manipulation
    if re.search(r'HTTP::header', content):
        analysis["mappable"].append({
            "feature": "Response header manipulation",
            "service_policy": "Response Headers Action in service policy",
            "event": "HTTP_RESPONSE"
        })
    
    # Response payload modification
    if re.search(r'HTTP::payload', content):
        analysis["unsupported"].append({
            "feature": "Response payload modification",
            "note": "Response body modification not directly supported",
            "event": "HTTP_RESPONSE"
        })
    
    # HSTS and security headers
    if re.search(r'Strict-Transport-Security|X-Frame-Options|Content-Security-Policy', content):
        analysis["mappable"].append({
            "feature": "Security Headers",
            "service_policy": "Load Balancer security settings",
            "notes": "Configure security headers in LB settings",
            "event": "HTTP_RESPONSE"
        })

def check_http_response_data_capabilities(content, analysis):
    """Analyze HTTP_RESPONSE_DATA event content"""
    if re.search(r'HTTP::payload', content):
        analysis["unsupported"].append({
            "feature": "Response data manipulation",
            "note": "Response payload modification not supported",
            "event": "HTTP_RESPONSE_DATA"
        })

def check_client_accepted_capabilities(content, analysis):
    """Analyze CLIENT_ACCEPTED event content"""
    
    # Client-side connection handling
    if re.search(r'TCP::|IP::', content):
        analysis["alternatives"].append({
            "feature": "Client connection handling",
            "alternative": "Use Load Balancer TCP/UDP settings",
            "event": "CLIENT_ACCEPTED"
        })

def check_server_connected_capabilities(content, analysis):
    """Analyze SERVER_CONNECTED event content"""
    
    # Server-side connection handling
    if re.search(r'TCP::|IP::', content):
        analysis["alternatives"].append({
            "feature": "Server connection handling",
            "alternative": "Configure in origin pool settings",
            "event": "SERVER_CONNECTED"
        })

def check_rule_init_capabilities(content, analysis):
    """Analyze RULE_INIT event content"""
    
    # Static variables
    if re.search(r'set\s+static::', content):
        analysis["alternatives"].append({
            "feature": "Static variable initialization",
            "alternative": "Use system metadata or configuration",
            "event": "RULE_INIT"
        })
    
    # Regular expressions
    if re.search(r'regexp|regex', content):
        analysis["mappable"].append({
            "feature": "Regular expression patterns",
            "service_policy": "Regular expression matching in rules",
            "event": "RULE_INIT"
        })

def check_clientssl_handshake_capabilities(content, analysis):
    """Analyze SSL/TLS handshake handling"""
    # SSL/TLS Info
    if re.search(r'SSL::cipher', content):
        analysis["mappable"].append({
            "feature": "SSL/TLS Information",
            "service_policy": "Available in XC logs",
            "notes": "SSL details automatically logged",
            "event": "CLIENTSSL_HANDSHAKE"
        })

    # SSL Session handling
    if re.search(r'SSL::sessionid', content):
        analysis["alternatives"].append({
            "feature": "SSL Session Persistence",
            "alternative": "Load Balancer persistence settings",
            "notes": "Configure appropriate persistence method",
            "event": "CLIENTSSL_HANDSHAKE"
        })

def check_clientssl_clientcert_capabilities(content, analysis):
    """Analyze client certificate handling"""
    if re.search(r'SSL::cert|X509::', content):
        analysis["mappable"].append({
            "feature": "Client Certificate Processing",
            "service_policy": "mTLS configuration and header injection",
            "notes": "XC supports mTLS and can extract X.509 attributes to headers",
            "event": "CLIENTSSL_CLIENTCERT"
        })

def generate_service_policy_template(analysis):
    """
    Generates a sample service policy template based on the analysis results
    """
    template = {
        "metadata": {
            "name": "converted-irule-policy",
            "namespace": "your-namespace"
        },
        "spec": {
            "rules": []
        }
    }
    
    rule_counter = 0
    
    # Add rules based on mappable features
    for feature in analysis["mappable"]:
        rule_counter += 1
        rule = {
            "name": f"rule-{rule_counter}",
            "action": "ALLOW",
            "conditions": [],
            "event": feature.get("event", "UNKNOWN")  # Include event information
        }
        
        if "URI" in feature["service_policy"]:
            rule["conditions"].append({
                "type": "URI_PATH",
                "pattern": "/*"
            })
        
        if "header" in feature["service_policy"].lower():
            rule["actions"] = {
                "headers": {
                    "add": {
                        "name": "X-Example",
                        "value": "value"
                    }
                }
            }
        
        if "redirect" in feature["service_policy"].lower():
            rule["action"] = "REDIRECT"
            rule["redirect"] = {
                "protocol": "HTTPS",
                "port": 443
            }
        
        template["spec"]["rules"].append(rule)
    
    return template
