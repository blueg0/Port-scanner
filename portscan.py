import nmap
nm = nmap.PortScanner()

target = "45.33.32.156"
options = "-sV -sC"

# Perform the scan
nm.scan(target, arguments=options)

# Print the scan results
for host in nm.all_hosts():
    print("Host: %s (%s)" % (host, nm[host].hostname()))
    print("State: %s" % nm[host].state())
    for protocol in nm[host].all_protocols():
        print("Protocol: %s" % protocol)
        port_info = nm[host][protocol]
        for port, state in port_info.items():
            print(f"Port: {port}")
            print(f"  State: {state['state']}")
            print(f"  Name: {state['name']}")
            if 'product' in state and state['product']:
                print(f"  Product: {state['product']}")
            if 'version' in state and state['version']:
                print(f"  Version: {state['version']}")
            if 'extrainfo' in state and state['extrainfo']:
                print(f"  Extra Info: {state['extrainfo']}")
            if 'script' in state and state['script']:
                for script_name, script_output in state['script'].items():
                    print(f"  {script_name}: {script_output}")
            print()
