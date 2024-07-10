## maybe this works 
import re
import os
#function to read config file
def parse_f5_config(f5_config_path):
  #read file
    with open(f5_config_path, 'r') as file:
        config_data = file.read()
    
    virtual_servers = []
    virtual_server_pattern = re.compile(r'ltm virtual ([\w-]+) {([^}]+)}', re.DOTALL)
    for match in virtual_server_pattern.finditer(config_data):
        virtual_server_name = match.group(1)
        virtual_server_config = match.group(2)
        
        ip_pattern = re.compile(r'destination ([\d\.]+):(\d+)')
        pool_pattern = re.compile(r'pool ([\w-]+)')
        ip_match = ip_pattern.search(virtual_server_config)
        pool_match = pool_pattern.search(virtual_server_config)
        
        if ip_match and pool_match:
            ip = ip_match.group(1)
            port = ip_match.group(2)
            pool = pool_match.group(1)
            virtual_servers.append({
                'name': virtual_server_name,
                'ip': ip,
                'port': port,
                'pool': pool
            })

    pools = {}
    pool_pattern = re.compile(r'ltm pool ([\w-]+) {([^}]+)}', re.DOTALL)
    for match in pool_pattern.finditer(config_data):
        pool_name = match.group(1)
        pool_config = match.group(2)
        
        members_pattern = re.compile(r'members {([^}]+)}', re.DOTALL)
        members_match = members_pattern.search(pool_config)
        
        if members_match:
            members = []
            member_pattern = re.compile(r'([\d\.]+):(\d+) {')
            for member_match in member_pattern.finditer(members_match.group(1)):
                member_ip = member_match.group(1)
                member_port = member_match.group(2)
                members.append({
                    'ip': member_ip,
                    'port': member_port
                })
            pools[pool_name] = members

    return virtual_servers, pools
#func to convert to haproxy
def convert_to_haproxy(virtual_servers, pools):
    """Convert parsed F5 config to HAProxy config format."""
    haproxy_config = []
    haproxy_config.append("global")
    haproxy_config.append("    log /dev/log local0")
    haproxy_config.append("    log /dev/log local1 notice")
    haproxy_config.append("    chroot /var/lib/haproxy")
  #change this line for API access
    haproxy_config.append("    stats socket /run/haproxy/admin.sock mode 660 level admin")
    haproxy_config.append("    stats timeout 30s")
    haproxy_config.append("    user haproxy")
    haproxy_config.append("    group haproxy")
    haproxy_config.append("    daemon")
    haproxy_config.append("")
    haproxy_config.append("defaults")
    haproxy_config.append("    log     global")
    haproxy_config.append("    mode    http")
    haproxy_config.append("    option  httplog")
    haproxy_config.append("    option  dontlognull")
    haproxy_config.append("    timeout connect 5000ms")
    haproxy_config.append("    timeout client  50000ms")
    haproxy_config.append("    timeout server  50000ms")
  ###  ADD WAF INIT  LINE 
    haproxy_config.append("")

    for virtual_server in virtual_servers:
        haproxy_config.append(f"frontend {virtual_server['name']}")
        haproxy_config.append(f"    bind {virtual_server['ip']}:{virtual_server['port']}")
        haproxy_config.append(f"    default_backend {virtual_server['name']}_backend")
        haproxy_config.append("")
        
        haproxy_config.append(f"backend {virtual_server['name']}_backend")
        for member in pools.get(virtual_server['pool'], []):
## maybe come advanced fancy http checks 
            haproxy_config.append(f"    server {member['ip'].replace('.', '_')}_{member['port']} {member['ip']}:{member['port']} check")
        haproxy_config.append("")

    return "\n".join(haproxy_config)
#maybe have to wirte config
def write_haproxy_config(haproxy_config, haproxy_config_path):
    with open(haproxy_config_path, 'w') as file:
        file.write(haproxy_config)

if __name__ == "__main__":
    f5_config_path = "f5config.conf"
    haproxy_config_path = "haproxy.cfg"

    # Check if F5 config esist
    if not os.path.exists(f5_config_path):
        print(f"F5 config file does not exist: {f5_config_path}")
    else:
        virtual_servers, pools = parse_f5_config(f5_config_path)
        haproxy_config = convert_to_haproxy(virtual_servers, pools)
        write_haproxy_config(haproxy_config, haproxy_config_path)
        print(f"WOW we write  config successfully to  ->> {haproxy_config_path}")
