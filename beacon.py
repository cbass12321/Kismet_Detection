from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import time

iface = "wlan1"  # your wireless interface in monitor mode

ssids_to_cast = []

# Gets the SSID's from file and adds them to an array
def get_ssids():
    """
    Function get_ssids
        - Opens text file named topSSID in same directory as the script
        - Appends each SSID name to the array ssid_list
    """
    with open("topSSID.txt", 'r') as f:
        lines = f.readlines()
        for line in lines:
            ssids_to_cast.append(line.strip())

# MAC of the sender
sender_mac = "00:11:22:33:44:55"

def beacon(ssid):
    # Craft the beacon frame
    beacon_frame = RadioTap()/Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)/Dot11Beacon(cap="ESS")/Dot11Elt(ID="SSID", info=ssid)

    # Send the frame
    sendp(beacon_frame, iface=iface, count=1)

def main():
    get_ssids()
    while True:  # Repeat indefinitely
        for ssid in ssids_to_cast:
            beacon(ssid)
            print(f'{ssid} Beacon Sent!')
            time.sleep(0.100)  # Delay between beacon frames

if __name__ in "__main__":
    main()
