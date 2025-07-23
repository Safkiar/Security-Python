#!/usr/bin/env python3

import subprocess
import optparse
import re


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Network interface (e.g. eth0)")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address to assign")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface using -i or --interface.")
    elif not options.new_mac:
        parser.error("[-] Please specify a new MAC address using -m or --mac.")
    return options


def change_mac(interface, new_mac):
    print(f"[+] Changing MAC address for {interface} to {new_mac}")
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


def get_current_mac(interface):
    try:
        ifconfig_result = subprocess.check_output(["ifconfig", interface])
        mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
        if mac_address_search_result:
            return mac_address_search_result.group(0)
        else:
            print("[-] Could not read MAC address.")
    except subprocess.CalledProcessError:
        print("[-] Failed to execute ifconfig command.")
    return None


options = get_arguments()
current_mac = get_current_mac(options.interface)

if current_mac:
    print(f"[i] Current MAC = {current_mac}")
else:
    print("[-] Could not get the current MAC address. Exiting.")
    exit(1)

change_mac(options.interface, options.new_mac)

current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac:
    print(f"[+] MAC address was successfully changed to {current_mac}")
else:
    print("[-] MAC address did not get changed.")