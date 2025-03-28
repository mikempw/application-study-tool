import re

def check_f5dc_compatibility(config):
    """
    Enhanced F5 DC compatibility checks with additional validation and uncertainty handling
    """
    incompatibilities = []
    warnings = []
    
    # Original incompatible features
    incompatible_features = [
        'asp', 'sip', 'rtsp', 'diameter', 'radius'
    ]

    # Load balancing method check
    lb_method = get_load_balancing_method(config)
    incompatible_lb_methods = [
        'ratio-member', 'ratio-node', 'ratio-session', 'weighted-least-connections-node',
        'observed-member', 'predictive-member', 'ratio-least-connections-member',
        'ratio-least-connections-node'
    ]
    
    if lb_method in incompatible_lb_methods:
        incompatibilities.append(f"Incompatible load balancing method: {lb_method}")

    # Hardware features check
    if has_hardware_features(config):
        incompatibilities.append("Uses hardware-specific features")

    # Basic feature check
    for feature in incompatible_features:
        if feature in config.lower():
            incompatibilities.append(f"Uses incompatible feature: {feature}")

    # Port compatibility check
    port_issues = check_port_compatibility(config)
    incompatibilities.extend(port_issues)

    # OneConnect check
    if has_oneconnect(config):
        warnings.append("Uses OneConnect - Possible, please investigate further")

    # Bot Defense check
    bot_defense_status = check_bot_defense(config)
    if bot_defense_status:
        warnings.append(bot_defense_status)

    # DNS checks
    dns_status = check_dns_compatibility(config)
    if dns_status:
        warnings.extend(dns_status)

    # API Security checks
    api_security_status = check_api_security(config)
    if api_security_status:
        warnings.extend(api_security_status)

    return {
        "incompatible": incompatibilities,
        "warnings": warnings
    }

def has_oneconnect(config):
    """Check for OneConnect profile usage"""
    oneconnect_patterns = [
        r'oneconnect\s+{',
        r'profile\s+oneconnect',
        r'source-mask'
    ]
    return any(re.search(pattern, config, re.IGNORECASE) for pattern in oneconnect_patterns)

def check_bot_defense(config):
    """Check Bot Defense configuration"""
    bot_patterns = [
        r'bot-defense\s+{',
        r'dos\s+bot-defense',
        r'bot-signature'
    ]
    if any(re.search(pattern, config, re.IGNORECASE) for pattern in bot_patterns):
        return "Uses Bot Defense - requires XC Bot Defense Standard or Advanced"
    return None

def check_dns_compatibility(config):
    """Check DNS configuration compatibility"""
    warnings = []
    
    dns_patterns = {
        r'gtm\s+wideip': "Uses DNS Wide IP - manual migration required",
        r'dns-express': "Uses DNS Express - manual migration required",
        r'zonerunner': "Uses Zonerunner - manual migration required",
        r'dns\s+zone': "Contains DNS zones - requires JSON/YAML conversion"
    }
    
    for pattern, message in dns_patterns.items():
        if re.search(pattern, config, re.IGNORECASE):
            warnings.append(message)
    
    return warnings

def check_api_security(config):
    """Check API Security configuration"""
    warnings = []
    
    api_patterns = {
        r'api-security': "Uses API Security - manual policy review required",
        r'openapi-spec': "Contains OpenAPI spec - can be imported to XC",
        r'swagger': "Contains Swagger/OpenAPI configuration - can be imported to XC"
    }
    
    for pattern, message in api_patterns.items():
        if re.search(pattern, config, re.IGNORECASE):
            warnings.append(message)
    
    return warnings

def check_port_compatibility(config):
    """
    Check for incompatible port numbers in the configuration.
    """
    incompatibilities = []
    
    # Individual incompatible ports
    incompatible_ports = {
        22, 53, 68, 323, 500, 1067, 2379, 2380, 4500, 5355, 
        6443, 8005, 8007, 8087, 8443, 8444, 8505, 8507, 9007, 
        9090, 9153, 9999, 10249, 10250, 10251, 10252, 10256, 
        10257, 10259, 18091, 18092, 18093, 18095, 22222, 23790, 
        23791, 23801, 23802
    }
    
    # Reserved port ranges
    reserved_ranges = [
        (28000, 32767, "volterra/kubernetes reserved port range")
    ]
    
    # Pattern to find port definitions in config
    port_patterns = [
        r'port\s+(\d+)',
        r'destination\s+\S+:(\d+)',
        r'source-port\s+(\d+)',
        r'target-port\s+(\d+)',
        r':(\d+)\s*{',  # Common F5 syntax for virtual servers
    ]
    
    # Check all port patterns
    for pattern in port_patterns:
        matches = re.finditer(pattern, config, re.IGNORECASE)
        for match in matches:
            port = int(match.group(1))
            
            # Check individual ports
            if port in incompatible_ports:
                incompatibilities.append(f"Uses incompatible port: {port}")
            
            # Check port ranges
            for start, end, description in reserved_ranges:
                if start <= port <= end:
                    incompatibilities.append(f"Uses port {port} from {description} ({start}-{end})")
    
    return incompatibilities

def get_load_balancing_method(config):
    """Original helper function preserved from inc.txt"""
    lb_match = re.search(r'load-balancing-mode\s+(\S+)', config)
    return lb_match.group(1) if lb_match else None

def has_hardware_features(config):
    """Original helper function preserved from inc.txt"""
    hardware_features = [
        'hardware-syncookie', 'hardware-syncookie-enabled',
        'hw-acceleration', 'hardware-acceleration',
        'fpga', 'tmc', 'tm.hardware'
    ]
    return any(feature in config.lower() for feature in hardware_features)

# Example usage
if __name__ == "__main__":
    sample_config = """
    ltm virtual /Common/test_vs {
        destination 10.0.0.1:8443
        ip-protocol tcp
        profiles {
            /Common/oneconnect { }
            /Common/bot-defense { }
        }
        rules {
            /Common/api-security
        }
    }
    """
    
    results = check_f5dc_compatibility(sample_config)
    print("Incompatibilities:", results["incompatible"])
    print("Warnings:", results["warnings"])
