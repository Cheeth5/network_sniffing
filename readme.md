# Network Packet Sniffer

A simple network packet sniffer built with Python. This tool captures and analyzes network packets in real-time.

## Features
- Capture live network traffic.
- Display packet details.
- Filter packets based on protocols.
- Save captured packets for offline analysis.

## Installation
1. Clone the repository:
    ```sh
    git clone https://github.com/your-username/network_packet_sniffer.git
    cd network_packet_sniffer
    ```

2. Install the required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

3. Run the application with elevated privileges:
    ```sh
    sudo python main.py
    ```

## Usage
- Enter the network interface to capture packets from (e.g., `eth0`, `wlan0`).
- Click the "Start Sniffing" button to begin capturing packets.

## Dependencies
Create a `requirements.txt` file with the following content:
Install the required Python libraries:
  pip install -r requirements.txt
Here's a README file for your Network Packet Sniffer project:

markdown

# Network Packet Sniffer

A Python-based network packet sniffer with a GUI interface. This application captures network packets, extracts source and destination IP addresses, and sends the information to a specified Discord channel in real-time.

## Features

- Captures network packets and extracts IP addresses.
- Sends captured packet information to a Discord channel via webhook.
- User-friendly GUI with modern design.
- Logging of captured packets.

## Prerequisites

- Python 3.6 or higher
- Required Python libraries:
  - `scapy`
  - `Pillow`
  - `requests`
- Network interface with permissions to capture packets (run with elevated privileges).

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network_packet_sniffer.git
   cd network_packet_sniffer
2.Install the required Python libraries:
   pip install -r requirements.txt
3.Running the Application:
  Ensure you have the necessary permissions to capture network packets. Run the script with elevated privileges:
    sudo python3 main.py
Configuration :

    Discord Webhook URL: Update the WEBHOOK_URL variable in the script with your Discord webhook URL.
Usage :

    This tool is intended for educational purposes and ethical hacking. Ensure you have proper authorization before capturing network traffic.
License:

  This project is licensed under the MIT License. See the LICENSE file for details.
Acknowledgements :

    Scapy
    Pillow
    Discord Webhooks
# Screenshots :





