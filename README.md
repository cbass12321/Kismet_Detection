# Wi-Fi SSID Tracker and Beacon Sender
Detect if a device is nearby based of probe packets captured using Kismet or anything else used for wardriving.

# Wi-Fi SSID Tracker and Beacon Sender

This project is a Python-based tool that leverages Wi-Fi probe requests and beacon frames for digital tracking. It includes functionality for capturing SSIDs, enabling/disabling monitor mode, crafting beacon frames, and storing data in a database. It also integrates Flask to serve a web interface and API routes for accessing data.

---

## **Features**
- Capture and track Wi-Fi SSIDs from probe requests.
- Store captured SSID information (e.g., MAC addresses, clients, last seen) in a SQLite database.
- Enable and disable network adapter modes (monitor, promiscuous, and managed).
- Craft and send custom Wi-Fi beacon frames.
- Web interface to visualize captured SSIDs and their associated metadata.
- REST API endpoints for retrieving marker and client data.

---

## **Requirements**
- Python 3.6 or higher
- Flask
- Flask-SQLAlchemy
- Scapy
- TShark (part of Wireshark)

## **Setup Instructions**

1. **Install Dependencies**:
   - Install Python libraries:
     ```bash
     pip install flask flask_sqlalchemy scapy
     ```
   - Install Wireshark and TShark:
     ```bash
     sudo apt-get install -y wireshark tshark
     ```

2. **Set Up Database**:
   - Ensure SQLite is installed.
   - The database will automatically initialize when the script is run for the first time.

3. **Prepare the Environment**:
   - Create a `topSSID.txt` file in the same directory as the script. Populate it with SSID names (one per line) that you want to monitor or beacon.

4. **Run the Script**:
   - Start the Flask server:
     ```bash
     python script_name.py
     ```
     
5. **Enable Monitor Mode**:
   - The script automatically enables monitor mode on the specified Wi-Fi adapter (e.g., `wlan1`). Ensure your network interface supports this mode.
  
## **Usage**

### **Capturing Probe Requests**
1. Specify the Wi-Fi interface to use in the `interface` variable or pass it as an argument when running the script.
2. Monitor for SSID broadcasts:
   - The script captures beacon frames (`wlan.fc.type_subtype == 0x8`) using TShark.
3. Match SSIDs:
   - If a detected SSID matches one in `topSSID.txt`, it stores the SSID, MAC address, and other metadata in the database.

### **Sending Beacon Frames**
1. Use the `send_beacon()` function:
   - Provide the SSID, interface, and sender MAC address.
   - Example:
     ```python
     send_beacon("ExampleSSID", "wlan1", "00:11:22:33:44:55")
     ```

### **Flask API Endpoints**
- `GET /getMarkers`: Returns all stored SSIDs and their metadata.
- `GET /getClients`: Returns all clients associated with captured SSIDs.

---

## **Considerations**
- **Permissions**: Root privileges are required for network interface operations and packet sniffing.
- **Security**: This tool is intended for educational and ethical purposes only. Ensure you have permission to analyze Wi-Fi traffic.
- **MAC Randomization**: Modern devices may use MAC address randomization, which limits tracking effectiveness.
- **Monitoring Interface**: Use a compatible Wi-Fi adapter that supports
