import re

def check_nginx_compatibility(config):
    incompatibilities = []
    
    f5_specific_features = [
        'ltm policy', 'asp', 'sip', 'rtsp', 'diameter', 'radius',
        'snat', 'nat64', 'oneconnect', 'clone-pools', 'gtm-score'
    ]
    for feature in f5_specific_features:
        if re.search(rf'\b{feature}\b.*?(?:enabled|{{)', config.lower()):
            incompatibilities.append(f"Uses F5-specific feature: {feature}")

    lb_method = get_load_balancing_method(config)
    nginx_compatible_lb_methods = [
        'round-robin', 'least-connections-member', 'least-connections-node',
        'fastest-node', 'ip-hash'
    ]
    if lb_method and lb_method not in nginx_compatible_lb_methods:
        incompatibilities.append(f"Incompatible load balancing method: {lb_method}")

    if has_hardware_features(config):
        incompatibilities.append("Uses F5 hardware acceleration features")

    ssl_features = ['client-ssl', 'server-ssl']
    for feature in ssl_features:
        if re.search(rf'\b{feature}\b', config.lower()):
            incompatibilities.append(f"Uses advanced SSL feature: {feature}")

    if re.search(r'\brules\s*{', config.lower()):
        incompatibilities.append("Uses iRules")

    if re.search(r'\bpersist\s*{', config.lower()):
        incompatibilities.append("Uses persistence profiles")

    return incompatibilities

def get_load_balancing_method(config):
    lb_match = re.search(r'load-balancing-mode\s+(\S+)', config)
    return lb_match.group(1) if lb_match else None

def has_hardware_features(config):
    hardware_features = [
        'hardware-syncookie', 'hardware-syncookie-enabled',
        'hw-acceleration', 'hardware-acceleration',
        'fpga', 'tmc', 'tm.hardware'
    ]
    return any(feature in config.lower() for feature in hardware_features)