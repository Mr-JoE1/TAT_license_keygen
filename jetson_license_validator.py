#!/usr/bin/env python3
import base64
import json
import os
import re
import subprocess
import socket
from datetime import datetime
from typing import Optional, Dict, List, Tuple, Union
import logging

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


logger = logging.getLogger(__name__)

class JetsonLicenseValidator:
    """License validator for Jetson boards running Linux"""
    
    # This is a fixed salt used for key derivation
    # In production, you should store this securely and not hardcode it
    SALT = b'TAT_LICENSE_SYSTEM_SALT'
    
    # This is a fixed password used for all licenses
    # In a real-world scenario, this should be kept secret
    SECRET_PASSWORD = b'eng.mohamed.maher2016@gmail.com'
    
    def __init__(self, 
                 key_file: str = '.key',
                 config_file: Optional[str] = None,
                 config_key_field: str = 'license_key',
                 app_name: str = 'Application'):
        """
        Initialize the license validator.
        
        Args:
            key_file: Path to the .key file containing the encrypted license key
            config_file: Optional path to a JSON config file containing the license key
            config_key_field: Field name in the config file containing the license key
            app_name: Name of the application (for error messages)
        """
        self.key_file = key_file
        self.config_file = config_file
        self.config_key_field = config_key_field
        self.app_name = app_name
        self.encrypted_license = None
        self.error_message = ""
        
        # System info
        self.mac_address = self._get_mac_address()
        self.baseboard_serial = self._get_baseboard_serial()
        
        # For storing decrypted license info
        self.license_info = {}
        self.is_valid = False
    
    def _get_mac_address(self) -> str:
        """Get the MAC address of the primary network interface."""
        try:
            # Try using ip command first (most reliable on modern Linux)
            result = subprocess.run(['ip', 'link', 'show'], 
                                   capture_output=True, text=True)
            output = result.stdout
            
            # Find primary interface (usually eth0 or enp0s3 but could be others)
            interfaces = []
            current_if = None
            for line in output.splitlines():
                if ': ' in line and not line.startswith(' '):
                    # This is an interface line
                    parts = line.split(': ')
                    if len(parts) >= 2:
                        if_name = parts[1].strip()
                        # Skip loopback
                        if 'lo' not in if_name:
                            current_if = if_name
                            interfaces.append(current_if)
                
                # Look for MAC in the details
                elif current_if and 'link/ether' in line:
                    mac = line.split('link/ether')[1].strip().split()[0].upper()
                    if mac != '00:00:00:00:00:00':
                        return mac
            
            # If no MAC found yet, try ifconfig
            if not interfaces:
                result = subprocess.run(['ifconfig'], 
                                       capture_output=True, text=True)
                output = result.stdout
                
                for line in output.splitlines():
                    if 'HWaddr' in line or 'ether' in line:
                        parts = line.strip().split()
                        for i, part in enumerate(parts):
                            if part in ['HWaddr', 'ether'] and i+1 < len(parts):
                                return parts[i+1].upper()
            
            # Last resort: try reading from /sys/class/net
            interfaces = os.listdir('/sys/class/net')
            for interface in interfaces:
                if interface != 'lo':  # Skip loopback
                    try:
                        with open(f'/sys/class/net/{interface}/address', 'r') as f:
                            mac = f.read().strip().upper()
                            if mac != '00:00:00:00:00:00':
                                return mac
                    except:
                        pass
        except:
            pass
        
        # Ultimate fallback
        return "00:00:00:00:00:00"
    
    def _get_baseboard_serial(self) -> str:
        """Get the baseboard serial number (specific to Jetson)."""
        try:
            # For Jetson devices
            if os.path.exists('/sys/firmware/devicetree/base/serial-number'):
                with open('/sys/firmware/devicetree/base/serial-number', 'r') as f:
                    serial = f.read().strip('\x00')
                    if serial:
                        return serial
            
            # Try to get from DMI info (standard on most Linux systems)
            if os.path.exists('/sys/class/dmi/id/board_serial'):
                with open('/sys/class/dmi/id/board_serial', 'r') as f:
                    serial = f.read().strip()
                    if serial and serial not in ['0', 'To be filled by O.E.M.']:
                        return serial
            
            # Try using dmidecode (requires root)
            try:
                result = subprocess.run(['sudo', 'dmidecode', '-s', 'baseboard-serial-number'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    serial = result.stdout.strip()
                    if serial and serial not in ['0', 'To be filled by O.E.M.']:
                        return serial
            except:
                pass
            
            # Try for Jetson-specific info using tegra commands
            try:
                result = subprocess.run(['cat', '/proc/device-tree/serial-number'], 
                                       capture_output=True, text=True)
                if result.returncode == 0:
                    serial = result.stdout.strip('\x00')
                    if serial:
                        return serial
            except:
                pass
            
            # Alternative method for Jetson using chip ID
            try:
                result = subprocess.run(['cat', '/sys/module/tegra_fuse/parameters/tegra_chip_id'], 
                                       capture_output=True, text=True)
                if result.returncode == 0:
                    chip_id = result.stdout.strip()
                    if chip_id:
                        return f"TEGRA-{chip_id}"
            except:
                pass
                
        except:
            pass
        
        # Fallback to hostname if no serial available
        return socket.gethostname()
    
    def _get_encryption_key(self) -> bytes:
        """
        Get the fixed encryption key used for all licenses.
        
        Returns:
            bytes: Fernet encryption key
        """
        # Use PBKDF2 to derive a key from the fixed password and salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256 bits
            salt=self.SALT,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.SECRET_PASSWORD))
        return key
    
    def load_license_key(self) -> bool:
        """
        Load the encrypted license from either config file or key file.
        
        Returns:
            bool: True if the license key was loaded successfully, False otherwise
        """
        # First try from config file if specified
        if self.config_file and os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                
                if self.config_key_field in config_data:
                    self.encrypted_license = config_data[self.config_key_field].strip()
                    #print(f"encrypted_license: {self.encrypted_license}")
                    return True
            except Exception as e:
                self.error_message = f"Failed to load license from config file: {str(e)}"
        
        # If no config file or config loading failed, try the key file
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, 'r') as f:
                    self.encrypted_license = f.read().strip()
                return True
            except Exception as e:
                self.error_message = f"Failed to load license from key file: {str(e)}"
        
        self.error_message = f"No valid license found for {self.app_name}"
        return False
    
    def validate_license(self) -> bool:
        """
        Validate the license key against the current device.
        
        Returns:
            bool: True if license is valid, False otherwise
        """
        if not self.encrypted_license:
            if not self.load_license_key():
                return False
        
        try:
            # Get fixed encryption key
            key = self._get_encryption_key()          
            # Create Fernet cipher
            cipher = Fernet(key)
            
            # Try to decrypt
            license_data_bytes = cipher.decrypt(self.encrypted_license.encode())
            license_data = json.loads(license_data_bytes.decode())
            #print(f"license_data: {license_data}")
            
            # If decryption succeeded, validate the license data
            # Check expiry date if exists
            if license_data.get('expiry_date') and license_data['expiry_date'] != 'None':
                try:
                    expiry_date = datetime.strptime(license_data['expiry_date'], '%Y-%m-%d')
                    if datetime.now() > expiry_date:
                        self.error_message = f"License expired on {license_data['expiry_date']}"
                        return False
                except:
                    pass  # If expiry format is invalid, continue with validation
            
            # Check device ID matches primary identifier or is in registered devices
            key_type = license_data.get('key_type', 'A')
            current_id = self.mac_address if key_type == 'A' else self.baseboard_serial
            
            # Get the list of registered devices
            registered_devices = license_data.get('registered_devices', [])
            
            # Check if primary identifier matches
            primary_identifier = license_data.get('identifier')
            if current_id == primary_identifier:
                self.license_info = license_data
                self.is_valid = True
                return True
            
            # Check if device is in registered list
            if current_id in registered_devices:
                self.license_info = license_data
                self.is_valid = True
                return True
            
            # Check if we're under the device limit and could potentially add this device
            device_limit = license_data.get('device_limit', 1)
            if len(registered_devices) < device_limit:
                # We have room to add this device, but can't modify the license from here
                # In a fully featured system, you might want to have a way to update the license
                self.error_message = f"Device not registered. This device: {current_id}"
                return False
            
            # If we got here, the device is not allowed
            self.error_message = f"Device limit reached ({device_limit})"
            return False
            
        except InvalidToken:
            self.error_message = "Invalid license key format or tampered license"
            return False
        except Exception as e:
            self.error_message = f"License validation error: {str(e)}"
            return False
    
    def get_device_ids(self) -> Dict[str, str]:
        """Get all device IDs."""
        return {
            'mac_address': self.mac_address,
            'baseboard_serial': self.baseboard_serial,
            'hostname': socket.gethostname()
        }
    
    def get_license_info(self) -> Dict:
        """
        Get information about the license if it's valid.
        Returns an empty dict if the license is not valid.
        """
        return self.license_info if self.is_valid else {}
    
    def get_error_message(self) -> str:
        """Get the last error message."""
        return self.error_message


def validate_license(app_name: str = "Application", 
                    key_file: str = '.key',
                    config_file: Optional[str] = None,
                    config_key_field: str = 'license_key') -> Tuple[bool, str, Dict]:
    """
    Convenience function to validate a license.
    
    Args:
        app_name: Name of the application
        key_file: Path to the license key file
        config_file: Optional path to a config JSON file containing the license key
        config_key_field: Field name in the config file containing the license key
        
    Returns:
        Tuple containing:
        - bool: True if license is valid, False otherwise
        - str: Error message if license is invalid, empty string otherwise
        - Dict: License information if available
    """
    validator = JetsonLicenseValidator(
        key_file=key_file,
        config_file=config_file,
        config_key_field=config_key_field,
        app_name=app_name
    )
    
    is_valid = validator.validate_license()
    error_message = validator.get_error_message() if not is_valid else ""
    license_info = validator.get_license_info()
    
    return is_valid, error_message, license_info

'''
# Example usage
if __name__ == "__main__":
    print("Jetson License Validator")
    print("-----------------------")
    
    # Try to validate using .key file first
    print("\nAttempting to validate license...")
    valid, error, license_info = validate_license(app_name="CAN UDP App")
    
    if valid:
        print("✓ License is valid!")
        print("\nLicense Information:")
        for key, value in license_info.items():
            print(f"  {key}: {value}")
    else:
        print(f"✗ License is invalid: {error}")
    
    # Display system information for debugging
    print("\nDevice Information:")
    validator = JetsonLicenseValidator()
    device_ids = validator.get_device_ids()
    
    print(f"  MAC Address: {device_ids['mac_address']}")
    print(f"  Baseboard Serial: {device_ids['baseboard_serial']}")
    print(f"  Hostname: {device_ids['hostname']}")
    
    # Check for config file
    config_file = 'config.json'
    if os.path.exists(config_file):
        print(f"\nConfig file '{config_file}' found, validating...")
        valid, error, license_info = validate_license(
            app_name="CAN UDP App", 
            config_file=config_file
        )
        
        if valid:
            print("✓ License in config file is valid!")
        else:
            print(f"✗ License in config file is invalid: {error}")
            
'''