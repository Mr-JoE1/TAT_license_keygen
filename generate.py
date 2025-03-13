import hashlib
import json

def generate_license_key(identifier, identifier_type, expiry_date=None, device_limit=10, registered_devices=None):
    """Generate a license key based on the identifier and type."""
    key_type = 'A' if identifier_type == 'mac' else 'B'
    
    # Prepare the list of devices
    if registered_devices is None:
        registered_devices = []
    
    # Create the license key format
    license_key = f"{key_type}|{device_limit}|{','.join(registered_devices)}|{expiry_date if expiry_date else 'None'}"
    
    # Hash the license key for storage
    hashed_key = hashlib.sha256(license_key.encode()).hexdigest()
    
    # Save the license info to a file
    license_info = {
        'license_key': hashed_key,
        'key_type': key_type,
        'identifier': identifier,
        'expiry_date': expiry_date,
        'device_limit': device_limit,
        'registered_devices': registered_devices  # This can be omitted for security
    }
    
    with open('license_info.json', 'w') as f:
        json.dump(license_info, f)
    
    with open('.key', 'w') as f:
        f.write(hashed_key)
    
    return hashed_key

# Example usage
baseboard_serial = "1423524332536"  # Replace with actual serial number
mac_address = "00:1A:2B:3C:4D:5E"  # Replace with actual MAC address
fake_mac_addresses = [
    "00:1A:2B:3C:4D:5E",
    "01:23:45:67:89:AB",
    "02:34:56:78:9A:BC",
    "03:45:67:89:AB:CD",
    "04:56:78:9A:BC:DE",
    "05:67:89:AB:CD:EF",
    "06:78:9A:BC:DE:F0",
    "07:89:AB:CD:EF:01",
    "08:9A:BC:DE:F0:12",
    "09:AB:CD:EF:01:23",
    "0A:BC:DE:F0:12:34",
    "0B:CD:EF:01:23:45",
    "0C:DE:F0:12:34:56",
    "0D:EF:01:23:45:67",
    "0E:01:23:45:67:89"
]

# Generate license based on motherboard serial number
license_key_baseboard = generate_license_key(baseboard_serial, 'baseboard', '2025-12-31', device_limit=10, registered_devices=[baseboard_serial])
print(f"Generated License Key (Baseboard): {license_key_baseboard}")

# Generate license based on MAC address
license_key_mac = generate_license_key(mac_address, 'mac', None, device_limit=10, registered_devices=fake_mac_addresses)  # Lifetime license
print(f"Generated License Key (MAC): {license_key_mac}")