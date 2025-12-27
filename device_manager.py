# device_manager.py - Manage multiple NetScaler devices
import json
import os
import logging
from typing import Dict, List, Optional
from netscaler import NetscalerClient, NetscalerError

logger = logging.getLogger("device_manager")

class DeviceManager:
    def __init__(self, config_file: str = "devices.json"):
        self.config_file = config_file
        self.devices = {}
        self.load_devices()

    def load_devices(self):
        """Load devices from JSON file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    self.devices = json.load(f)
                logger.info(f"Loaded {len(self.devices)} devices from {self.config_file}")
            except Exception as e:
                logger.error(f"Error loading devices: {e}")
                self.devices = {}
        else:
            # Create default device if config doesn't exist
            self.devices = {
                "default": {
                    "host": "10.1.1.101",
                    "username": "nsroot",
                    "password": "kailas@123",
                    "name": "Default NetScaler",
                    "description": "Primary NetScaler device"
                }
            }
            self.save_devices()

    def save_devices(self):
        """Save devices to JSON file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.devices, f, indent=2)
            logger.info(f"Saved {len(self.devices)} devices to {self.config_file}")
        except Exception as e:
            logger.error(f"Error saving devices: {e}")

    def add_device(self, device_id: str, name: str, host: str, username: str, password: str, description: str = "") -> bool:
        """Add a new device"""
        if device_id in self.devices:
            return False

        self.devices[device_id] = {
            "name": name,
            "host": host,
            "username": username,
            "password": password,
            "description": description
        }
        self.save_devices()
        logger.info(f"Added device: {device_id} ({name})")
        return True

    def remove_device(self, device_id: str) -> bool:
        """Remove a device"""
        if device_id not in self.devices:
            return False

        del self.devices[device_id]
        self.save_devices()
        logger.info(f"Removed device: {device_id}")
        return True

    def get_device(self, device_id: str) -> Optional[Dict]:
        """Get device configuration"""
        return self.devices.get(device_id)

    def get_all_devices(self) -> Dict[str, Dict]:
        """Get all devices"""
        return self.devices.copy()

    def test_device_connection(self, device_id: str) -> tuple[bool, str]:
        """Test connection to a device"""
        device = self.get_device(device_id)
        if not device:
            return False, "Device not found"

        try:
            ns = NetscalerClient(device["host"], device["username"], device["password"])
            ns.close()
            return True, "Connection successful"
        except NetscalerError as e:
            return False, str(e)
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"

    def get_client(self, device_id: str) -> Optional[NetscalerClient]:
        """Get NetscalerClient for a device"""
        device = self.get_device(device_id)
        if not device:
            return None

        try:
            return NetscalerClient(device["host"], device["username"], device["password"])
        except NetscalerError:
            return None

# Global device manager instance
device_manager = DeviceManager()
