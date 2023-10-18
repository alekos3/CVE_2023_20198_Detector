__author__ = "Alexios Nersessian"
__email__ = "nersessian@gmail.com"
__version__ = "v1"

import argparse
import getpass
import time
from multiprocessing.pool import ThreadPool
import netmiko
import csv

"""
    Cisco IOS XE Software Web UI Privilege Escalation Vulnerability CVE-2023-20198
    https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z
"""

# Initialize Arg parser
arg_parser = argparse.ArgumentParser(prog=__doc__)

arg_parser.add_argument(
    "-d",
    "--devices",
    required=False,
    type=str,
    default="devices.csv",
    help="File with all IP addresses. Must be a csv file."
)

args = vars(arg_parser.parse_args())


class SshHandler:
    def __init__(self, ip, username, password):
        self.ip = ip
        self.username = username
        self.password = password
        self.ssh = None

    def get_ssh_connection(self):
        try:

            device = {
                "device_type": "cisco_ios",
                "host": self.ip,
                "username": self.username,
                "password": self.password,
                "port": 22,
                "fast_cli": False

            }
            ssh = netmiko.ConnectHandler(**device)

        except:
            return False

        self.ssh = ssh

        return True

    def close_ssh_connection(self):
        try:
            self.ssh.disconnect()

        except Exception as e:
            print(f"Could not close SSH connection {self.ip}")
            print(e)
            return False

        return True

    def send_command(self, command, collect_output=True):
        try:
            if collect_output:
                output = self.ssh.send_command(command)
                return output
            else:
                self.ssh.send_command(command, expect_string=r"#")

        except Exception as e:
            if collect_output:
                print(f"Could not get output for command - {command}")
            # print(e)
            return False


def get_devices_from_csv(filename):
    # Open the CSV file
    with open(filename, 'r') as file:
        data = file.read()

    return data.splitlines()


def write_to_csv(data, current_timestamp):
    # Prepare data for csv
    csv_data = [['IP', 'Vulnerabilities Found']]
    for ip, info in data.items():
        vulnerabilities = ', '.join(info['vulnerable']) if info['vulnerable'] else 'NO'
        csv_data.append([ip, vulnerabilities])

    # Write to csv
    with open(f'Results_CVE_2023_20198_{current_timestamp}.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(csv_data)


def main(host):
    global RESULTS
    RESULTS[host] = {'vulnerable': []}
    vuln_commands = ["show running-config | include ip http server",
                     "show running-config | include ip http secure-server",
                     "show running-config | include ip http active"]

    # 1. Establish connection to host
    print(f"- Connecting to {host}.")
    connection = SshHandler(host, username, password)
    status = connection.get_ssh_connection()

    if not status:
        print(f"- {host}: Failed to connect.")
        return

    for command in vuln_commands:
        result = connection.send_command(command, collect_output=True)

        if host in RESULTS and "no " not in result and result:
            RESULTS[host]["vulnerable"].append(result)

        elif "no " not in result and result:
            RESULTS[host] = {"vulnerable": [result]}

    if RESULTS[host].get("vulnerable"):
        print("-", host, "Vulnerable!")
    else:
        print("-", host, "Not vulnerable.")


if __name__ == '__main__':
    current_timestamp = time.strftime('%m-%d-%Y-%H_%M')  # USA Date Format
    RESULTS = {}
    username = input("Enter username: ")
    password = getpass.getpass()
    host_list = get_devices_from_csv(args["devices"])[1:]

    #  Multi threading
    pool = ThreadPool(10)  # Number of threads, do NOT increase
    pool.map(main, host_list)
    pool.close()  # Close needs to be first before join as per docs, or we will run into memory issue
    pool.join()  # https://docs.python.org/2/library/multiprocessing.html#module-multiprocessing.pool

    write_to_csv(RESULTS, current_timestamp)
    print()
    print("Done!")
    print(f'For results check: Results_CVE_2023_20198_{current_timestamp}.csv')
    print()
