#!/usr/bin/env python3
"""Test script to verify NetScaler connection error handling"""

from netscaler import NetscalerClient, NetscalerError

def test_unreachable_device():
    """Test connecting to an unreachable device"""
    try:
        print("Attempting to connect to unreachable NetScaler device...")
        ns = NetscalerClient('10.1.1.10', 'test_user', 'test_pass')
        print("ERROR: Connection should have failed!")
        ns.close()
    except NetscalerError as e:
        print(f"SUCCESS: NetscalerError properly caught: {str(e)}")
        return True
    except Exception as e:
        print(f"ERROR: Unexpected exception type: {type(e).__name__}: {str(e)}")
        return False

if __name__ == "__main__":
    test_unreachable_device()
