from flask import Flask, render_template, request, jsonify
import requests
import traceback
import urllib3
import re
import os
import uuid
from clickhouse_driver import Client
from nginx_compatibility import check_nginx_compatibility
from f5dc_compatibility import check_f5dc_compatibility
from irule_analyzer import analyze_irule

# Disable SSL warnings - in production, you'd want to handle this properly
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

def store_analysis_in_clickhouse(results, hostname, username):
    """Store analysis results in Clickhouse database"""
    try:
        client = Client(
            host=os.environ.get('CLICKHOUSE_HOST', 'clickhouse'),
            port=int(os.environ.get('CLICKHOUSE_PORT', 9000)),
            user=os.environ.get('CLICKHOUSE_USER', 'default'),
            password=os.environ.get('CLICKHOUSE_PASSWORD', 'password'),
            database=os.environ.get('CLICKHOUSE_DATABASE', 'f5_analyzer')
        )
        
        # Create a unique session ID for this analysis
        session_id = uuid.uuid4()
        
        # Store session data
        client.execute(
            "INSERT INTO analysis_sessions (id, hostname, username, summary_virtual_servers, summary_pools, summary_irules, summary_asm_policies, summary_apm_policies) VALUES",
            [(
                session_id,
                hostname,
                username,
                results['summary']['virtual_servers'],
                results['summary']['pools'],
                results['summary']['irules'],
                results['summary']['asm_policies'],
                results['summary']['apm_policies']
            )]
        )
        
        # Store virtual server data
        for vs in results['virtual_servers']:
            vs_id = uuid.uuid4()
            
            # Convert lists to arrays for Clickhouse
            nginx_compat = vs.get('nginx_compatibility', [])
            f5dc_compat = vs.get('f5dc_compatibility', [])
            f5dc_warnings = vs.get('f5dc_warnings', [])
            
            has_issues = 1 if (nginx_compat or f5dc_compat) else 0
            
            client.execute(
                "INSERT INTO virtual_servers (id, session_id, name, partition, full_path, destination, pool, has_compatibility_issues, nginx_compatibility_issues, f5dc_compatibility_issues, f5dc_warnings) VALUES",
                [(
                    vs_id,
                    session_id,
                    vs.get('name', ''),
                    vs.get('partition', 'Common'),
                    vs.get('fullPath', f"/{vs.get('partition', 'Common')}/{vs.get('name', '')}"),
                    vs.get('destination', ''),
                    vs.get('pool', ''),
                    has_issues,
                    nginx_compat,
                    f5dc_compat,
                    f5dc_warnings
                )]
            )
            
            # Store iRule analysis data
            if 'irules_analysis' in vs and vs['irules_analysis']:
                for irule in vs['irules_analysis']:
                    analysis = irule.get('analysis', {})
                    
                    # Extract features from each category
                    mappable = [item.get('feature', '') for item in analysis.get('mappable', [])]
                    alternatives = [item.get('feature', '') for item in analysis.get('alternatives', [])]
                    unsupported = [item.get('feature', '') for item in analysis.get('unsupported', [])]
                    warnings = [item.get('feature', '') for item in analysis.get('warnings', [])]
                    events = list(analysis.get('events', {}).keys())
                    
                    client.execute(
                        "INSERT INTO irule_analysis (session_id, virtual_server_id, name, partition, full_path, mappable_features, alternative_features, unsupported_features, warnings, events) VALUES",
                        [(
                            session_id,
                            vs_id,
                            irule.get('name', ''),
                            irule.get('partition', 'Common'),
                            irule.get('fullPath', irule.get('name', '')),
                            mappable,
                            alternatives,
                            unsupported,
                            warnings,
                            events
                        )]
                    )
        
        return True, session_id
    except Exception as e:
        app.logger.error(f"Error storing data in Clickhouse: {str(e)}")
        return False, str(e)

class F5BIGIPAnalyzer:
    def __init__(self):
        self.api_base = None
        self.session = None

    def analyze(self, hostname, port, username, password):
        try:
            # Set up the REST API connection
            self.api_base = f"https://{hostname}:{port}/mgmt/tm"
            self.session = requests.Session()
            self.session.auth = (username, password)
            self.session.verify = False  # In production, use proper certificate verification
            
            # Test connection
            print(f"Attempting to connect to {hostname}:{port} as {username}")
            response = self.session.get(f"{self.api_base}/sys/version")
            response.raise_for_status()
            print("REST API connection established successfully")
            
            # Check if bash utility is available (for advanced configuration fetching)
            try:
                bash_test = self.session.post(
                    f"https://{hostname}:{port}/mgmt/tm/util/bash",
                    json={"command": "run", "utilCmdArgs": "-c 'echo test'"}
                )
                bash_test.raise_for_status()
                print("Bash utility available for advanced configuration fetching")
            except Exception as e:
                print(f"Warning: Bash utility not available - falling back to API-only mode: {str(e)}")
            
            # Fetch all partitions
            print("Fetching partitions...")
            partitions = self.get_partitions()
            print(f"Found {len(partitions)} partitions")

            # Fetch configuration components across all partitions
            print("Fetching virtual servers...")
            virtual_servers = self.get_virtual_servers(partitions)
            print(f"Found {len(virtual_servers)} virtual servers")
            
            print("Fetching pools...")
            pools = self.get_pools(partitions)
            print(f"Found {len(pools)} pools")
            
            print("Fetching iRules...")
            irules = self.get_irules(partitions)
            print(f"Found {len(irules)} iRules")
            
            print("Fetching ASM policies...")
            asm_policies = self.get_asm_policies()
            print(f"Found {len(asm_policies)} ASM policies")
            
            print("Fetching APM policies...")
            apm_policies = self.get_apm_policies()
            print(f"Found {len(apm_policies)} APM policies")
            
            print("Generating report...")
            report = self.generate_report(virtual_servers, pools, irules, asm_policies, apm_policies)
            
            print("Analysis completed successfully")
            return report
            
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error: {http_err}")
            raise
        except requests.exceptions.ConnectionError as conn_err:
            print(f"Connection error: {conn_err}")
            raise
        except requests.exceptions.Timeout as timeout_err:
            print(f"Timeout error: {timeout_err}")
            raise
        except requests.exceptions.RequestException as req_err:
            print(f"Request error: {req_err}")
            raise
        except Exception as e:
            print(f"An unexpected error occurred during analysis: {str(e)}")
            raise

    def get_partitions(self):
        """Get all partitions from the F5 BIG-IP"""
        try:
            response = self.session.get(f"{self.api_base}/auth/partition")
            response.raise_for_status()
            data = response.json()
            
            partitions = []
            for item in data.get('items', []):
                partitions.append(item.get('name', ''))
            
            return partitions
        except Exception as e:
            print(f"Error getting partitions: {str(e)}")
            # If we can't get partitions, default to Common
            return ['Common']

    def get_virtual_servers(self, partitions=None):
        """Get virtual servers from all partitions or specified partitions"""
        all_virtual_servers = []
        
        # If partitions not specified, use 'all' which will retrieve from all partitions
        if not partitions:
            try:
                response = self.session.get(f"{self.api_base}/ltm/virtual?expandSubcollections=true")
                response.raise_for_status()
                data = response.json()
                
                for item in data.get('items', []):
                    vs_name = item.get('fullPath', item.get('name', ''))
                    try:
                        # Get the full tmsh formatted configuration
                        cmd_response = self.session.post(
                            f"https://{self.api_base.split('/')[2]}/mgmt/tm/util/bash",
                            json={
                                "command": "run",
                                "utilCmdArgs": f"-c 'tmsh -q list ltm virtual {vs_name} all-properties'"
                            }
                        )
                        cmd_response.raise_for_status()
                        config_str = cmd_response.json().get('commandResult', '')
                    except Exception as e:
                        print(f"Warning: Could not get tmsh configuration for {vs_name}: {str(e)}")
                        config_str = str(item)  # Fallback to JSON string representation
                        
                    all_virtual_servers.append({
                        'type': 'ltm virtual',
                        'name': item.get('name', ''),
                        'partition': item.get('partition', 'Common'),
                        'fullPath': vs_name,
                        'config': config_str,
                        'raw_data': item
                    })
                
                return all_virtual_servers
            except Exception as e:
                print(f"Error getting virtual servers: {str(e)}")
                return []
        
        # Otherwise, iterate through each partition
        for partition in partitions:
            try:
                print(f"Fetching virtual servers from partition: {partition}")
                response = self.session.get(f"{self.api_base}/ltm/virtual?$filter=partition+eq+{partition}&expandSubcollections=true")
                response.raise_for_status()
                data = response.json()
                
                for item in data.get('items', []):
                    vs_name = item.get('fullPath', item.get('name', ''))
                    try:
                        # Get the full tmsh formatted configuration
                        cmd_response = self.session.post(
                            f"https://{self.api_base.split('/')[2]}/mgmt/tm/util/bash",
                            json={
                                "command": "run",
                                "utilCmdArgs": f"-c 'tmsh -q list ltm virtual {vs_name} all-properties'"
                            }
                        )
                        cmd_response.raise_for_status()
                        config_str = cmd_response.json().get('commandResult', '')
                    except Exception as e:
                        print(f"Warning: Could not get tmsh configuration for {vs_name}: {str(e)}")
                        config_str = str(item)  # Fallback to JSON string representation
                        
                    all_virtual_servers.append({
                        'type': 'ltm virtual',
                        'name': item.get('name', ''),
                        'partition': partition,
                        'fullPath': vs_name,
                        'config': config_str,
                        'raw_data': item
                    })
            except Exception as e:
                print(f"Error getting virtual servers from partition {partition}: {str(e)}")
        
        return all_virtual_servers

    def get_pools(self, partitions=None):
        """Get pools from all partitions or specified partitions"""
        all_pools = []
        
        # If partitions not specified, use 'all' which will retrieve from all partitions
        if not partitions:
            try:
                response = self.session.get(f"{self.api_base}/ltm/pool?expandSubcollections=true")
                response.raise_for_status()
                data = response.json()
                
                for item in data.get('items', []):
                    pool_name = item.get('fullPath', item.get('name', ''))
                    try:
                        # Get the full tmsh formatted configuration
                        cmd_response = self.session.post(
                            f"https://{self.api_base.split('/')[2]}/mgmt/tm/util/bash",
                            json={
                                "command": "run",
                                "utilCmdArgs": f"-c 'tmsh -q list ltm pool {pool_name} all-properties'"
                            }
                        )
                        cmd_response.raise_for_status()
                        config_str = cmd_response.json().get('commandResult', '')
                    except Exception as e:
                        print(f"Warning: Could not get tmsh configuration for pool {pool_name}: {str(e)}")
                        config_str = str(item)  # Fallback to JSON string representation
                        
                    all_pools.append({
                        'type': 'ltm pool',
                        'name': item.get('name', ''),
                        'partition': item.get('partition', 'Common'),
                        'fullPath': pool_name,
                        'config': config_str,
                        'raw_data': item
                    })
                
                return all_pools
            except Exception as e:
                print(f"Error getting pools: {str(e)}")
                return []
        
        # Otherwise, iterate through each partition
        for partition in partitions:
            try:
                print(f"Fetching pools from partition: {partition}")
                response = self.session.get(f"{self.api_base}/ltm/pool?$filter=partition+eq+{partition}&expandSubcollections=true")
                response.raise_for_status()
                data = response.json()
                
                for item in data.get('items', []):
                    pool_name = item.get('fullPath', item.get('name', ''))
                    try:
                        # Get the full tmsh formatted configuration
                        cmd_response = self.session.post(
                            f"https://{self.api_base.split('/')[2]}/mgmt/tm/util/bash",
                            json={
                                "command": "run",
                                "utilCmdArgs": f"-c 'tmsh -q list ltm pool {pool_name} all-properties'"
                            }
                        )
                        cmd_response.raise_for_status()
                        config_str = cmd_response.json().get('commandResult', '')
                    except Exception as e:
                        print(f"Warning: Could not get tmsh configuration for pool {pool_name}: {str(e)}")
                        config_str = str(item)  # Fallback to JSON string representation
                        
                    all_pools.append({
                        'type': 'ltm pool',
                        'name': item.get('name', ''),
                        'partition': partition,
                        'fullPath': pool_name,
                        'config': config_str,
                        'raw_data': item
                    })
            except Exception as e:
                print(f"Error getting pools from partition {partition}: {str(e)}")
        
        return all_pools

    def get_irules(self, partitions=None):
        """
        Get iRules from all partitions or specified partitions,
        with improved error handling and parsing for TCL content
        """
        all_irules = []
        
        # Helper function to process iRule data
        def process_irule(item, partition='Common'):
            irule_name = item.get('fullPath', item.get('name', ''))
            api_config = str(item)
            
            # Extract actual TCL content if available in apiAnonymous field
            tcl_content = ""
            if 'apiAnonymous' in item:
                tcl_content = item['apiAnonymous']
            
            # If we couldn't get TCL content from API, try using bash utility
            if not tcl_content.strip() or 'when' not in tcl_content:
                try:
                    # Get the full tmsh formatted configuration
                    cmd_response = self.session.post(
                        f"https://{self.api_base.split('/')[2]}/mgmt/tm/util/bash",
                        json={
                            "command": "run",
                            "utilCmdArgs": f"-c 'tmsh -q list ltm rule {irule_name}'"
                        }
                    )
                    cmd_response.raise_for_status()
                    config_str = cmd_response.json().get('commandResult', '')
                    
                    # Extract the actual content between the braces
                    content_match = re.search(r'\{([^}]+)\}$', config_str, re.DOTALL)
                    if content_match:
                        tcl_content = content_match.group(1).strip()
                except Exception as e:
                    print(f"Warning: Could not get TCL content for iRule {irule_name} via bash: {str(e)}")
            
            # Use the TCL content as config if we got it, otherwise fall back to API response
            if tcl_content and 'when' in tcl_content:
                config_str = tcl_content
            else:
                config_str = api_config
            
            all_irules.append({
                'type': 'ltm rule',
                'name': item.get('name', ''),
                'partition': partition,
                'fullPath': irule_name,
                'config': config_str,
                'tcl_content': tcl_content,  # Store the TCL content separately
                'raw_data': item
            })
        
        # If partitions not specified, use 'all' which will retrieve from all partitions
        if not partitions:
            try:
                response = self.session.get(f"{self.api_base}/ltm/rule?expandSubcollections=true")
                response.raise_for_status()
                data = response.json()
                
                for item in data.get('items', []):
                    process_irule(item, item.get('partition', 'Common'))
                
                return all_irules
            except Exception as e:
                print(f"Error getting iRules: {str(e)}")
                # Fall back to simpler approach
                try:
                    response = self.session.get(f"{self.api_base}/ltm/rule")
                    response.raise_for_status()
                    data = response.json()
                    
                    for item in data.get('items', []):
                        all_irules.append({
                            'type': 'ltm rule',
                            'name': item.get('name', ''),
                            'partition': item.get('partition', 'Common'),
                            'fullPath': item.get('fullPath', ''),
                            'config': str(item),
                            'raw_data': item
                        })
                    return all_irules
                except Exception as fallback_error:
                    print(f"Fallback error getting iRules: {str(fallback_error)}")
                    return []
        
        # Otherwise, iterate through each partition
        for partition in partitions:
            try:
                print(f"Fetching iRules from partition: {partition}")
                response = self.session.get(f"{self.api_base}/ltm/rule?$filter=partition+eq+{partition}&expandSubcollections=true")
                response.raise_for_status()
                data = response.json()
                
                for item in data.get('items', []):
                    process_irule(item, partition)
            except Exception as e:
                print(f"Error getting iRules from partition {partition}: {str(e)}")
                # Try fallback approach for this partition
                try:
                    response = self.session.get(f"{self.api_base}/ltm/rule?$filter=partition+eq+{partition}")
                    response.raise_for_status()
                    data = response.json()
                    
                    for item in data.get('items', []):
                        all_irules.append({
                            'type': 'ltm rule',
                            'name': item.get('name', ''),
                            'partition': partition,
                            'fullPath': item.get('fullPath', ''),
                            'config': str(item),
                            'raw_data': item
                        })
                except Exception as fallback_error:
                    print(f"Fallback error getting iRules from partition {partition}: {str(fallback_error)}")
        
        return all_irules

    def get_asm_policies(self):
        try:
            response = self.session.get(f"{self.api_base}/asm/policies")
            response.raise_for_status()
            data = response.json()
            
            asm_policies = []
            for item in data.get('items', []):
                config_str = str(item)
                asm_policies.append({
                    'type': 'asm policy',
                    'name': item.get('name', ''),
                    'partition': item.get('partition', 'Common'),
                    'config': config_str,
                    'raw_data': item
                })
            return asm_policies
        except requests.exceptions.HTTPError:
            # ASM might not be enabled on this F5
            print("Note: ASM module might not be enabled")
            return []

    def get_apm_policies(self):
        try:
            response = self.session.get(f"{self.api_base}/apm/policy")
            response.raise_for_status()
            data = response.json()
            
            apm_policies = []
            for item in data.get('items', []):
                config_str = str(item)
                apm_policies.append({
                    'type': 'apm policy',
                    'name': item.get('name', ''),
                    'partition': item.get('partition', 'Common'),
                    'config': config_str,
                    'raw_data': item
                })
            return apm_policies
        except requests.exceptions.HTTPError:
            # APM might not be enabled on this F5
            print("Note: APM module might not be enabled")
            return []

    def generate_report(self, virtual_servers, pools, irules, asm_policies, apm_policies):
        report = {
            "summary": {
                "virtual_servers": len(virtual_servers),
                "pools": len(pools),
                "irules": len(irules),
                "asm_policies": len(asm_policies),
                "apm_policies": len(apm_policies)
            },
            "virtual_servers": [],
            "irules_analysis": {}  # Add iRule analysis section
        }

        # Process iRules and add analysis
        for irule in irules:
            if 'config' in irule and irule['config'] and 'when' in irule['config']:
                try:
                    analysis = analyze_irule(irule['config'])
                    report["irules_analysis"][irule['fullPath'] if 'fullPath' in irule else irule['name']] = analysis
                except Exception as e:
                    print(f"Error analyzing iRule {irule.get('fullPath', irule.get('name', 'unknown'))}: {str(e)}")
                    report["irules_analysis"][irule['fullPath'] if 'fullPath' in irule else irule['name']] = {"error": str(e)}

        for vs in virtual_servers:
            # Extract the irules attached to this VS
            vs_irules = self.extract_irules(vs)
            
            # For each irule referenced, find its configuration
            irule_configs = []
            irule_analysis_results = []
            irule_incompatibilities = []  # Track iRule-specific incompatibilities
            
            for irule_name in vs_irules:
                # The irule_name might already be a full path or just a name
                # If it's just a name, we need to check in the right partition
                vs_partition = vs.get('partition', 'Common')
                
                # Try to match by fullPath first
                matching_irule = next((ir for ir in irules if ir.get('fullPath', '') == irule_name), None)
                
                # If not found, try to match by name and partition
                if not matching_irule:
                    clean_name = irule_name.split('/')[-1] if '/' in irule_name else irule_name
                    matching_irule = next((ir for ir in irules if ir['name'] == clean_name and ir.get('partition', 'Common') == vs_partition), None)
                
                # If still not found, try by name only
                if not matching_irule:
                    clean_name = irule_name.split('/')[-1] if '/' in irule_name else irule_name
                    matching_irule = next((ir for ir in irules if ir['name'] == clean_name), None)
                
                if matching_irule:
                    irule_configs.append(matching_irule['config'])
                    
                    # Get the irule identifier for analysis lookup
                    irule_id = matching_irule.get('fullPath', matching_irule.get('name', ''))
                    
                    # Get analysis for this iRule if available
                    if irule_id in report["irules_analysis"]:
                        irule_analysis = report["irules_analysis"][irule_id]
                        irule_analysis_results.append({
                            "name": matching_irule.get('name', ''),
                            "partition": matching_irule.get('partition', 'Common'),
                            "fullPath": irule_id,
                            "analysis": irule_analysis
                        })
                        
                        # Extract incompatibilities from iRule analysis
                        if "unsupported" in irule_analysis and irule_analysis["unsupported"]:
                            for item in irule_analysis["unsupported"]:
                                irule_incompatibilities.append(f"iRule {irule_id} uses unsupported feature: {item['feature']}")
                        
                        # Also consider alternatives as potential incompatibilities
                        if "alternatives" in irule_analysis and irule_analysis["alternatives"]:
                            for item in irule_analysis["alternatives"]:
                                irule_incompatibilities.append(f"iRule {irule_id} needs alternative: {item['feature']}")
            
            # Combine virtual server config with all its irules for compatibility check
            combined_config = vs['config']
            for irule_config in irule_configs:
                combined_config += "\n" + irule_config
            
            # Run compatibility checks
            nginx_compat = check_nginx_compatibility(combined_config)
            f5dc_compat_result = check_f5dc_compatibility(combined_config)
            
            # Handle the enhanced F5DC compatibility result format
            f5dc_incompatibilities = []
            f5dc_warnings = []
            
            if isinstance(f5dc_compat_result, dict):
                # New format with incompatibilities and warnings
                f5dc_incompatibilities = f5dc_compat_result.get("incompatible", [])
                f5dc_warnings = f5dc_compat_result.get("warnings", [])
            else:
                # Old format - just a list of incompatibilities
                f5dc_incompatibilities = f5dc_compat_result
            
            # Add iRule-specific incompatibilities to the f5dc incompatibilities
            f5dc_incompatibilities.extend(irule_incompatibilities)
            
            vs_report = {
                "name": vs['name'],
                "partition": vs.get('partition', 'Common'),
                "fullPath": vs.get('fullPath', f"/{vs.get('partition', 'Common')}/{vs['name']}"),
                "destination": self.extract_destination(vs),
                "pool": self.extract_pool(vs),
                "pool_members": self.get_pool_members(vs, pools),
                "irules": vs_irules,
                "irules_analysis": irule_analysis_results,
                "nginx_compatibility": nginx_compat,
                "f5dc_compatibility": f5dc_incompatibilities,
                "f5dc_warnings": f5dc_warnings
            }
            report["virtual_servers"].append(vs_report)

        return report

    def extract_destination(self, vs):
        raw_data = vs.get('raw_data', {})
        if 'destination' in raw_data:
            # The destination in API response might be in the format of '/partition/address:port'
            destination = raw_data['destination']
            if isinstance(destination, str):
                return destination
            elif isinstance(destination, dict) and 'name' in destination:
                return destination['name']
        return "Not specified"

    def extract_pool(self, vs):
        raw_data = vs.get('raw_data', {})
        if 'pool' in raw_data:
            pool = raw_data['pool']
            if isinstance(pool, str):
                return pool
            elif isinstance(pool, dict) and 'name' in pool:
                return pool['name']
        return "None"

    def get_pool_members(self, vs, pools):
        pool_name = self.extract_pool(vs)
        if pool_name == "None":
            return []
        
        # The pool name might be a full path or just a name
        vs_partition = vs.get('partition', 'Common')
        
        # Try to match by fullPath first
        pool_config = next((p for p in pools if p.get('fullPath', '') == pool_name), None)
        
        # If not found, try to match by name and partition
        if not pool_config:
            clean_name = pool_name.split('/')[-1] if '/' in pool_name else pool_name
            pool_config = next((p for p in pools if p['name'] == clean_name and p.get('partition', 'Common') == vs_partition), None)
        
        # If still not found, try by name only
        if not pool_config:
            clean_name = pool_name.split('/')[-1] if '/' in pool_name else pool_name
            pool_config = next((p for p in pools if p['name'] == clean_name), None)
            
        if not pool_config:
            return []
            
        pool_data = pool_config.get('raw_data', {})
        members = []
        
        # Members are typically in a subcollection named 'membersReference'
        members_ref = pool_data.get('membersReference', {})
        if 'items' in members_ref:
            for member in members_ref.get('items', []):
                member_name = member.get('name', '')
                address = ''
                
                # Try to extract address from 'address' field
                if 'address' in member:
                    address = member['address']
                # Alternatively, the name might already be in format 'name:port'
                elif ':' in member_name:
                    address = member_name.split(':')[0]
                    
                members.append({
                    "name": member_name,
                    "address": address,
                    "partition": member.get('partition', pool_config.get('partition', 'Common'))
                })
                
        return members

    def extract_irules(self, vs):
        """
        Extract iRules associated with a virtual server.
        First try to parse from the config string, then fall back to raw data.
        """
        # First try to get rules from config string, which will work if we got the tmsh output
        config = vs.get('config', '')
        irules_match = re.findall(r'rules\s*{\s*([^}]+)}', config)
        if irules_match and irules_match[0].strip():
            return irules_match[0].split()
            
        # Fallback to API data if regex didn't find anything
        raw_data = vs.get('raw_data', {})
        if 'rules' in raw_data:
            rules = raw_data['rules']
            return rules if isinstance(rules, list) else []
            
        return []

    def parse_config(self, config_str):
        configs = re.split(r'\n(?=ltm |asm |apm )', config_str)
        parsed_configs = []
        for config in configs:
            if config.strip():
                name = re.search(r'^(\w+\s+\w+\s+)(\S+)\s*{', config)
                if name:
                    parsed_configs.append({
                        'type': name.group(1).strip(),
                        'name': name.group(2),
                        'config': config
                    })
        return parsed_configs

analyzer = F5BIGIPAnalyzer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        hostname = request.form['hostname']
        port = request.form.get('port', 443)  # Default to HTTPS port
        username = request.form['username']
        password = request.form['password']

        results = analyzer.analyze(hostname, port, username, password)
        
        # Store analysis results in Clickhouse
        store_success, session_id = store_analysis_in_clickhouse(results, hostname, username)
        if store_success:
            app.logger.info(f"Analysis stored in Clickhouse with session ID: {session_id}")
            # Add the session ID to the results so it can be referenced
            results["session_id"] = str(session_id)
        else:
            app.logger.warning(f"Failed to store analysis in Clickhouse: {session_id}")
        
        return jsonify(results)
    except Exception as e:
        error_traceback = traceback.format_exc()
        app.logger.error(f"An error occurred:\n{error_traceback}")
        return jsonify({"error": str(e), "traceback": error_traceback}), 500

@app.route('/history', methods=['GET'])
def history():
    """View analysis history from Clickhouse"""
    try:
        client = Client(
            host=os.environ.get('CLICKHOUSE_HOST', 'clickhouse'),
            port=int(os.environ.get('CLICKHOUSE_PORT', 9000)),
            user=os.environ.get('CLICKHOUSE_USER', 'default'),
            password=os.environ.get('CLICKHOUSE_PASSWORD', 'password'),
            database=os.environ.get('CLICKHOUSE_DATABASE', 'f5_analyzer')
        )
        
        # Get last 100 analysis sessions
        sessions = client.execute("""
            SELECT 
                id,
                timestamp,
                hostname,
                username,
                summary_virtual_servers,
                summary_pools,
                summary_irules,
                summary_asm_policies,
                summary_apm_policies
            FROM analysis_sessions
            ORDER BY timestamp DESC
            LIMIT 100
        """)
        
        # Format the results for display
        history_data = []
        for session in sessions:
            history_data.append({
                "id": str(session[0]),
                "timestamp": session[1].strftime("%Y-%m-%d %H:%M:%S"),
                "hostname": session[2],
                "username": session[3],
                "summary": {
                    "virtual_servers": session[4],
                    "pools": session[5],
                    "irules": session[6],
                    "asm_policies": session[7],
                    "apm_policies": session[8]
                }
            })
        
        return jsonify({"sessions": history_data})
    except Exception as e:
        error_traceback = traceback.format_exc()
        app.logger.error(f"An error retrieving history:\n{error_traceback}")
        return jsonify({"error": str(e), "traceback": error_traceback}), 500

@app.route('/session/<session_id>', methods=['GET'])
def get_session(session_id):
    """Get details for a specific analysis session"""
    try:
        client = Client(
            host=os.environ.get('CLICKHOUSE_HOST', 'clickhouse'),
            port=int(os.environ.get('CLICKHOUSE_PORT', 9000)),
            user=os.environ.get('CLICKHOUSE_USER', 'default'),
            password=os.environ.get('CLICKHOUSE_PASSWORD', 'password'),
            database=os.environ.get('CLICKHOUSE_DATABASE', 'f5_analyzer')
        )
        
        # Get session summary
        session_data = client.execute("""
            SELECT 
                id,
                timestamp,
                hostname,
                username,
                summary_virtual_servers,
                summary_pools,
                summary_irules,
                summary_asm_policies,
                summary_apm_policies
            FROM analysis_sessions
            WHERE id = %(session_id)s
        """, {"session_id": session_id})
        
        if not session_data:
            return jsonify({"error": "Session not found"}), 404
        
        session = session_data[0]
        
        # Get virtual servers for this session
        virtual_servers = client.execute("""
            SELECT 
                id,
                name,
                partition,
                full_path,
                destination,
                pool,
                has_compatibility_issues,
                nginx_compatibility_issues,
                f5dc_compatibility_issues,
                f5dc_warnings
            FROM virtual_servers
            WHERE session_id = %(session_id)s
        """, {"session_id": session_id})
        
        vs_data = []
        for vs in virtual_servers:
            vs_id = vs[0]
            
            # Get iRule analysis for this virtual server
            irule_analysis = client.execute("""
                SELECT 
                    name,
                    partition,
                    full_path,
                    mappable_features,
                    alternative_features,
                    unsupported_features,
                    warnings,
                    events
                FROM irule_analysis
                WHERE virtual_server_id = %(vs_id)s
            """, {"vs_id": vs_id})
            
            irules_data = []
            for ir in irule_analysis:
                irules_data.append({
                    "name": ir[0],
                    "partition": ir[1],
                    "fullPath": ir[2],
                    "analysis": {
                        "mappable": [{"feature": feature} for feature in ir[3]],
                        "alternatives": [{"feature": feature} for feature in ir[4]],
                        "unsupported": [{"feature": feature} for feature in ir[5]],
                        "warnings": [{"feature": feature} for feature in ir[6]],
                        "events": {event: "" for event in ir[7]}
                    }
                })
            
            vs_data.append({
                "name": vs[1],
                "partition": vs[2],
                "fullPath": vs[3],
                "destination": vs[4],
                "pool": vs[5],
                "has_compatibility_issues": bool(vs[6]),
                "nginx_compatibility": vs[7],
                "f5dc_compatibility": vs[8],
                "f5dc_warnings": vs[9],
                "irules_analysis": irules_data
            })
        
        # Construct response
        response = {
            "id": str(session[0]),
            "timestamp": session[1].strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": session[2],
            "username": session[3],
            "summary": {
                "virtual_servers": session[4],
                "pools": session[5],
                "irules": session[6],
                "asm_policies": session[7],
                "apm_policies": session[8]
            },
            "virtual_servers": vs_data
        }
        
        return jsonify(response)
    except Exception as e:
        error_traceback = traceback.format_exc()
        app.logger.error(f"Error retrieving session {session_id}:\n{error_traceback}")
        return jsonify({"error": str(e), "traceback": error_traceback}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
