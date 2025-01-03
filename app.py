# Defining imports
import subprocess
import sys
import os
from flask import Flask, render_template, jsonify, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

# Setup flask app
app = Flask(__name__)

# Setup flask database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ssid.db'
db = SQLAlchemy(app)

# Create database model
class SSID(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    mac = db.Column(db.String(100), nullable=False)
    last_seen = db.Column(db.String(100), nullable=False)
    clients = db.Column(db.String(100), nullable=False)
    latitude = db.Column(db.String(100), nullable=False)
    longitude = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return '<SSID %r>' % self.name

    # Serialize function for JSON
    def serialize(self):
        return {
            'name': self.name,
            'mac': self.mac,
            'last_seen': self.last_seen,
            'clients': self.clients,
            'latitude': self.latitude,
            'longitude': self.longitude
        }
    
# List of SSID names to listen for
ssid_list = []

# List of SSID names to beacon
beacon_list = []

# Check installation status of 'tshark'
def is_tshark_installed():
    """
    Function is_tshark_installed
        - Checks through terminal if tshark is installed.
        - If it is not installed, it will return False
        - If it is installed, it will return True
    """
    try:
        subprocess.check_output(['tshark', '-v'])
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        return False

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
            ssid_list.append(line.strip())
            beacon_list.append(line.strip())

# Enables promiscious mode (we also need monitor mode for beacon packets)
def change_adapter(mode):
    """
    Function change_adapter
    Args: MODE (Managed, Promiscious, Monitor)
        - Disables interface
        - Sets adapter mode to MODE
        - Enables interface
    """
    
    if mode == "promisc":
        # Set the interface to use promiscuous mode
        subprocess.run(["sudo", "ifconfig", interface, mode], check=True)

        # Check if promiscuous mode is enabled
        result = subprocess.run(["ifconfig", interface], capture_output=True, text=True)
        
        if "PROMISC" in result.stdout:
            print(f"Promiscuous mode is enabled on interface {interface}")
        else:
            print(f"Failed to enable promiscuous mode on interface {interface}")
            
    # Set interface mode to monitor
    elif mode == "monitor":
        subprocess.run(["sudo", "ifconfig", interface, "down"])
        subprocess.run(["sudo", "iwconfig", interface, "mode", "monitor"], check=True)
        subprocess.run(["sudo", "ifconfig", interface, "up"])

        # Check if monitor mode is enabled
        result = subprocess.run(["iwconfig", interface], capture_output=True, text=True)
        
        if "Monitor" in result.stdout:
            print(f"Monitor mode is enabled on interface {interface}")
        else:
            print(f"Failed to enable monitor mode on interface {interface}")
            
    # Set interface mode to monitor
    elif mode == "managed":
        subprocess.run(["sudo", "ifconfig", interface, "down"])
        subprocess.run(["sudo", "iwconfig", interface, "mode", "managed"], check=True)
        subprocess.run(["sudo", "ifconfig", interface, "up"])

        # Check if monitor mode is enabled
        result = subprocess.run(["iwconfig", interface], capture_output=True, text=True)
        
        if "Managed" in result.stdout:
            print(f"Managed mode is enabled on interface {interface}")
        else:
            print(f"Failed to enable managed mode on interface {interface}")
    else:
        print("Invalid option! Please enter ('promisc', 'monitor', or 'managed')")

# Function to send out beacon packets
def send_beacon(ssid, interface, sender_mac):
    """
    Function send_beacon
    Args: SSID (SSID name), INTERFACE (eth0, wlan0, wlan1), SENDER_MAC (MAC address of sender)
        - Crafts beacon frame
        - Sends beacon frame
    """
    # Craft the beacon frame
    beacon_frame = RadioTap()/Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)/Dot11Beacon(cap="ESS")/Dot11Elt(ID="SSID", info=ssid)

    # Send the frame
    sendp(beacon_frame, iface=interface, count=1)

# Main function
def main(interface):
    """
    Function main
    Args: INTERFACE (eth0, wlan0, wlan1)
        - Grabs SSID's from file
        - Enables Monitor Mode
        - Starts tshark (command-line Wireshark)
        - Filters out everthing except Beacon packets
        - If match found in ssid_list, display the MAC and SSID.
    """
    get_ssids()

    # Enable monitor mode
    change_adapter('monitor')

    # Start tcpdump to listen for packets on the interface
    process = subprocess.Popen(["sudo", "tshark", "-i", interface, "-Y", "wlan.fc.type_subtype == 0x8"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        # Process each line of output from tcpdump
        for line in iter(process.stdout.readline, b''):
            line = line.decode("utf-8").strip()

            # Check if the line contains a beacon frame
            ssid = line.split("SSID=")[-1]

            # Check if the SSID is in the list of SSIDs to listen for
            if ssid in ssid_list:
                mac_address = line.split(" → Broadcast")[0].split(" ")[-1]

                # Check if SSID is already in the database
                if SSID.query.filter_by(name=ssid).first() is None:
                    
                    # Add SSID to database
                    new_ssid = SSID(name=ssid, mac=mac_address, last_seen="1", clients="1", latitude="1", longitude="1")
                    db.session.add(new_ssid)
                else:
                    # Append mac address to clients column
                    ssid = SSID.query.filter_by(name=ssid).first()
                    ssid.clients = f"{ssid.clients}, {mac_address}"
                db.session.commit()
                # Display MAC address and associated SSID
                print(f"MAC: {mac_address} - SSID: {ssid}")
    finally:
        # Kill the tcpdump process when the program is stopped
        process.kill()

        # Sets adapter to managed mode (default)
        change_adapter('managed')

# Flask Render Template Routes
@app.route('/')
def index_page():
    return render_template('index.html')

@app.route('/map')
def map_page():
    return render_template('map.html')

# Flask API Routes
@app.route('/getMarkers', methods=['GET'])
def get_markers():
    markers = SSID.query.all()
    return jsonify({'markers': [marker.serialize() for marker in markers]})

@app.route('/getClients', methods=['GET'])
def get_clients():
    clients = SSID.query.all()
    return jsonify({clients.name: clients.clients for clients in clients})
    

# Starting the main function
if __name__ in "__main__":
    app.run(debug=True)

    
    # if is_tshark_installed():
    #     # TShark already installed
    #     # Defining interface as wlan1 or whatever is passed to the script
    #     interface = str(sys.argv[-1])

    #     if "py" in interface:
    #         interface = 'wlan1'
    #     main(interface)
    # else:
    #     print('TShark is not installed... installing')

    #     # Install TShark

    #     subprocess.run(["sudo", "apt-get", "install", "-y", "tshark"], check=True)

    #     # Restarting the script
    #     os.execv(sys.executable, ['python3'] + sys.argv)
    #     print("TShark succesfully installed. Restarting script...")
    # else:
    #     print("Unknown OS. Exiting...")
    