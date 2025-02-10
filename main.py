#!/usr/bin/env python3
import paramiko
import sys
import ipaddress
import argparse
from scp import SCPClient

# Configuration file path on the device
REMOTE_CONFIG_PATH = '/tmp/system.cfg'
BACKUP_CONFIG_PATH = '/tmp/system.cfg.backup'

# SNMP parameters to be configured
SNMP_ENABLE_LINE = 'snmp.status=enabled'
SNMP_COMMUNITY_LINE = 'snmp.community=YOUR_COMMUNITY'  # Change as needed
SNMP_CONTACT_LINE = 'snmp.contact=YOUR_CONTACT'  # Change as needed
SNMP_LOCATION_LINE = 'snmp.location=YOUR_LOCATION'  # Change as needed

def create_ssh_connection(host, credentials_list):
    """
    Attempts to establish an SSH connection with the device using each username-password combination.
    Uses the 'disabled_algorithms' parameter to disable 'rsa-sha1',
    allowing the use of the ssh-dss algorithm if necessary.
    Returns the SSHClient object if authentication is successful or None otherwise.
    """
    for username, password in credentials_list:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                host,
                username=username,
                password=password,
                timeout=10,
                disabled_algorithms={'pubkeys': ['rsa-sha1']}
            )
            print(f"Successfully connected to {host} using {username}:{password}!")
            return client
        except paramiko.AuthenticationException:
            print(f"Authentication failed for {host} with {username}:{password}. Trying next combination...")
        except Exception as e:
            print(f"Error connecting to {host} with {username}:{password}: {e}")
            # If another exception occurs, stop attempts for this host
            break
    return None

def execute_command(client, command):
    """
    Executes a command on the device and returns (stdout, stderr, exit_status).
    """
    stdin, stdout, stderr = client.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    return stdout.read().decode(), stderr.read().decode(), exit_status

def backup_config(client):
    """
    Creates a backup of the configuration file on the device.
    """
    cmd = f'cp {REMOTE_CONFIG_PATH} {BACKUP_CONFIG_PATH}'
    stdout, stderr, status = execute_command(client, cmd)
    if status == 0:
        print("Backup successfully created.")
    else:
        print("Failed to create backup:", stderr)
        raise Exception("Error creating backup.")

def download_config_with_scp(ssh_client, local_config_file):
    """
    Downloads the configuration file from the device to the local machine via SCP.
    """
    try:
        with SCPClient(ssh_client.get_transport()) as scp:
            scp.get(REMOTE_CONFIG_PATH, local_config_file)
        print("Configuration file successfully downloaded via SCP.")
    except Exception as e:
        raise Exception(f"Failed to download configuration file via SCP: {e}")

def update_local_config(local_config_file):
    """
    Reads the local configuration file, updates the SNMP parameters, and saves the changes.
    Now checks for lines starting with 'snmp.status' and 'snmp.community'.
    """
    try:
        with open(local_config_file, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        raise Exception(f"Error reading local file: {e}")

    found_snmp_status = False
    found_snmp_community = False
    found_snmp_contact = False
    found_snmp_location = False
    new_lines = []

    for line in lines:
        if line.startswith('snmp.status'):
            new_lines.append(SNMP_ENABLE_LINE + '\n')
            found_snmp_status = True
        elif line.startswith('snmp.community'):
            new_lines.append(SNMP_COMMUNITY_LINE + '\n')
            found_snmp_community = True
        elif line.startswith('snmp.contact'):
            new_lines.append(SNMP_CONTACT_LINE + '\n')
            found_snmp_contact = True
        elif line.startswith('snmp.location'):
            new_lines.append(SNMP_LOCATION_LINE + '\n')
            found_snmp_location = True
        else:
            new_lines.append(line)

    if not found_snmp_status:
        new_lines.append(SNMP_ENABLE_LINE + '\n')
    if not found_snmp_community:
        new_lines.append(SNMP_COMMUNITY_LINE + '\n')
    if not found_snmp_contact:
        new_lines.append(SNMP_CONTACT_LINE + '\n')
    if not found_snmp_location:
        new_lines.append(SNMP_LOCATION_LINE + '\n')

    try:
        with open(local_config_file, 'w') as f:
            f.writelines(new_lines)
        print("Configuration file successfully updated locally.")
    except Exception as e:
        raise Exception(f"Error saving local file: {e}")

def upload_config_with_scp(ssh_client, local_config_file):
    """
    Uploads the updated configuration file to the device via SCP.
    """
    try:
        with SCPClient(ssh_client.get_transport()) as scp:
            scp.put(local_config_file, REMOTE_CONFIG_PATH)
        print("Configuration file successfully uploaded via SCP.")
    except Exception as e:
        raise Exception(f"Failed to upload configuration file via SCP: {e}")

def save_permanent_config(client):
    """
    Executes the command to save the configuration permanently on the device.
    """
    cmd = 'cfgmtd -w -p /etc'
    stdout, stderr, status = execute_command(client, cmd)
    if status == 0:
        print("Configuration saved permanently.")
    else:
        print("Failed to save configuration permanently:", stderr)
        raise Exception("Error saving permanent configuration.")

def soft_reboot(client):
    """
    Softly restarts the device (without cutting power).
    """
    try:
        stdin, stdout, stderr = client.exec_command("/usr/etc/rc.d/rc.softrestart save")
        print("Applying new configuration using rc.softrestart.")
    except Exception as e:
        print(f"Error restarting the device: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Script to configure SNMP on Ubiquiti (AirOS) devices in a network."
    )
    parser.add_argument(
        "network",
        help="IP range in CIDR format (e.g., 192.168.1.0/24)"
    )
    args = parser.parse_args()

    try:
        network = ipaddress.ip_network(args.network, strict=False)
    except ValueError as e:
        print(f"Error parsing network address: {e}")
        sys.exit(1)

    devices = list(network.hosts())
    if not devices:
        print("No hosts found in the provided network.")
        sys.exit(1)

    # Change as needed
    credentials = [
        ("user1", "pass1"),
        ("user2", "pass2"),
        ("user3", "pass3"),
        ("user4", "pass4"),
    ]

    for host in devices:
        host_str = str(host)
        print(f"\nProcessing device: {host_str}")

        ssh_client = create_ssh_connection(host_str, credentials)
        if ssh_client is None:
            print(f"Unable to authenticate on device {host_str}. Skipping...")
            continue

        local_config_file = f"./configs/system_{host_str.replace('.', '_')}.cfg"

        try:
            backup_config(ssh_client)
            download_config_with_scp(ssh_client, local_config_file)
            update_local_config(local_config_file)
            upload_config_with_scp(ssh_client, local_config_file)
            save_permanent_config(ssh_client)
            soft_reboot(ssh_client)
        except Exception as e:
            print(f"Error processing {host_str}: {e}")
        finally:
            ssh_client.close()

if __name__ == '__main__':
    main()