# SNMP Configuration Script for Ubiquiti (AirOS) Devices

## Description
This Python script automates the configuration of SNMP settings on Ubiquiti (AirOS) devices within a given network range. It establishes an SSH connection, modifies the device's configuration file, and saves the changes permanently.

## Features
- Attempts SSH authentication using multiple credential combinations.
- Creates a backup of the existing configuration file.
- Downloads the configuration file via SCP.
- Updates SNMP settings locally.
- Uploads the modified configuration file back to the device.
- Saves the configuration permanently.
- Performs a soft reboot to apply changes.

## Prerequisites
### Required Packages
Ensure you have the following Python packages installed:
```sh
pip install paramiko scp
```

### Device Compatibility
- This script is designed for Ubiquiti (AirOS) devices.
- Devices must have SSH access enabled.
- Devices should allow SCP file transfers.

## Usage
Run the script with the following command:
```sh
python3 script.py <network-cidr>
```
Example:
```sh
python3 script.py 192.168.1.0/24
```

## Configuration
The script modifies the following SNMP parameters, change then as needed:
- `snmp.status=enabled`
- `snmp.community=YOUR_COMMUNITY`
- `snmp.contact=YOUR_CONTACT`
- `snmp.location=YOUR_LOCATION`

## Authentication
The script will try a list of username-password combinations for SSH authentication, change then and/or add other combinations depending on your devices configurations:
- `user1 / pass1`
- `user2 / pass2`
- `user3 / pass3`
- `user4 / pass4`

## Script Flow
1. Identifies all hosts within the provided network range.
2. Attempts SSH authentication using predefined credentials.
3. If authentication succeeds:
   - Creates a backup of the current configuration.
   - Downloads the configuration file via SCP.
   - Modifies the SNMP settings in the configuration file.
   - Uploads the modified configuration file via SCP.
   - Saves the changes permanently.
   - Performs a soft reboot.
4. If authentication fails, the script moves to the next host.

## Error Handling
- If SSH authentication fails, the script moves to the next device.
- If an error occurs during the process, it logs the error and continues with the next host.

## Disclaimer
Use this script at your own risk. Ensure you have proper permissions before modifying network device configurations.

## License
This project is licensed under the MIT License.

