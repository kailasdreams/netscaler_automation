#!/usr/bin/env python3
"""
Test script to verify unreachable device handling in NetScaler automation.
"""

import logging
from netscaler import NetscalerClient

# Set up logging to see the output
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Mock NetscalerClient for testing (since we don't have a real NetScaler)
class MockNetscalerClient:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password

    def create_servicegroup(self, sg_name, servicetype="HTTP"):
        print(f"Would create servicegroup: {sg_name}")
        return True

    def add_service_member(self, sg_name, ip, port):
        # Simulate some devices being unreachable
        unreachable_ips = ["192.168.1.100", "10.0.0.50"]
        if ip in unreachable_ips:
            print(f"Simulating unreachable device: {ip}:{port}")
            return False
        print(f"Successfully added member: {ip}:{port} to {sg_name}")
        return True

    def create_lbvserver(self, vname, vip, port, servicetype):
        print(f"Would create LB vserver: {vname} ({vip}:{port})")
        return True

    def bind_servicegroup_to_vserver(self, vname, sg_name):
        print(f"Would bind servicegroup {sg_name} to vserver {vname}")
        return True

    def bind_ssl_cert_to_vserver(self, vname, certkey):
        print(f"Would bind SSL cert {certkey} to vserver {vname}")
        return True

    def bind_monitor_to_servicegroup(self, sg_name, monitor):
        print(f"Would bind monitor {monitor} to servicegroup {sg_name}")
        return True

    def create_vip(self, vip_name, vip, vip_port, servicetype, sg_name, nodes, monitor=None, certkey=None):
        added_members = []
        failed_members = []

        # create SG
        self.create_servicegroup(sg_name, servicetype)

        # add members - continue even if some fail
        for n in nodes:
            try:
                ip, prt = n.split(":")
                ip = ip.strip()
                port = int(prt)
                if self.add_service_member(sg_name, ip, port):
                    added_members.append(f"{ip}:{port}")
                else:
                    failed_members.append(f"{ip}:{port}")
            except ValueError as e:
                print(f"Invalid node format '{n}': {str(e)}")
                failed_members.append(n)
            except Exception as e:
                print(f"Error processing node '{n}': {str(e)}")
                failed_members.append(n)

        # create vserver
        self.create_lbvserver(vip_name, vip, vip_port, servicetype)
        # bind SG
        self.bind_servicegroup_to_vserver(vip_name, sg_name)
        # bind SSL if required
        if servicetype.upper() == "SSL" and certkey:
            self.bind_ssl_cert_to_vserver(vip_name, certkey)
        # bind monitor if provided
        if monitor:
            self.bind_monitor_to_servicegroup(sg_name, monitor)

        return {
            'vip_name': vip_name,
            'added_members': added_members,
            'failed_members': failed_members
        }

def test_device_handling():
    print("Testing device handling with unreachable devices...")
    print("=" * 50)

    # Create mock client
    ns = MockNetscalerClient("mock-host", "admin", "password")

    # Test with mixed reachable and unreachable devices
    nodes = [
        "192.168.1.10:80",    # reachable
        "192.168.1.100:80",   # unreachable (simulated)
        "10.0.0.20:8080",     # reachable
        "10.0.0.50:8080",     # unreachable (simulated)
        "172.16.1.5:443"      # reachable
    ]

    result = ns.create_vip(
        vip_name="TEST_VIP",
        vip="10.10.10.100",
        vip_port=80,
        servicetype="HTTP",
        sg_name="test_sg",
        nodes=nodes,
        monitor="http-ecv"
    )

    print("\n" + "=" * 50)
    print("RESULTS:")
    print(f"VIP Name: {result['vip_name']}")
    print(f"Successfully added: {result['added_members']}")
    print(f"Failed/Skipped: {result['failed_members']}")
    print(f"Success rate: {len(result['added_members'])}/{len(nodes)} devices")

if __name__ == "__main__":
    test_device_handling()
