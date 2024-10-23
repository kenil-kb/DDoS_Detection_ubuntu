import tkinter as tk
from tkinter import messagebox, simpledialog
import subprocess
import os
import sys
import pyshark
import psutil
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
import sklearn.ensemble._forest
from threading import Thread, Event
import csv
import time
import requests

# Global variable for thread control
stop_event = Event()
value = False

# Important features and weights as provided
important_features = [
    'pktcount',
    'byteperflow',
    'tot_kbps',
    'rx_kbps',
    'flows',
    'bytecount',
    'tot_dur',
    'Protocol_ICMP',
    'Protocol_TCP',
    'Protocol_UDP',
]


# Drop features you don't need based on what you used in training
drop_features = ['src', 'dst', 'dt', 'dur', 'pktrate', 'pktperflow',
  
    'Protocol_HTTP',
    'Protocol_HTTPS',
    'Protocol_SSH',
    'Protocol_DHCP',
    'Protocol_FTP',
    'Protocol_SMTP',
    'Protocol_POP3',
    'Protocol_IMAP',
    'Protocol_DNS']

# Automatically detect active network interface
def get_active_interface():
    interfaces = psutil.net_if_addrs()
    
    for interface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == 2:  # family=2 corresponds to AF_INET (IPv4)
                if addr.address != '127.0.0.1':  # Skip localhost (lo)
                    return interface
    raise Exception("No active interface found")

# Preprocessing function to extract specific features from packets
def preprocess_packet(packet):
    try:
        if float(packet.frame_info.time_delta) < 1:
            byteperflow = float(packet.length)
        else:
            byteperflow = float(packet.length) / float(packet.frame_info.time_delta)

        # Capture IP or IPv6 addresses
        src_ip = None
        dst_ip = None
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
        elif hasattr(packet, 'ipv6'):
            src_ip = packet.ipv6.src
            dst_ip = packet.ipv6.dst
        if(src_ip and ':' in src_ip ):
            return None

        # Capture protocol layer (handles protocols other than ICMP, TCP, UDP)
        protocol = packet.highest_layer

        # Add flags for common protocols (ICMP, TCP, UDP are already covered)
        protocol_icmp = 1 if protocol == "ICMP" else 0
        protocol_tcp = 1 if protocol == "TCP" else 0
        protocol_udp = 1 if protocol == "UDP" else 0
        protocol_http = 1 if protocol == "HTTP" else 0
        protocol_https = 1 if protocol == "SSL" else 0  # HTTPS typically uses SSL/TLS layer
        protocol_ssh = 1 if protocol == "SSH" else 0
        protocol_dhcp = 1 if protocol in ["DHCP", "BOOTP"] else 0  # DHCP may appear as BOOTP
        protocol_ftp = 1 if protocol == "FTP" else 0
        protocol_smtp = 1 if protocol == "SMTP" else 0
        protocol_pop3 = 1 if protocol == "POP" else 0
        protocol_imap = 1 if protocol == "IMAP" else 0
        protocol_dns = 1 if protocol == "DNS" else 0

        features = {
            'pktcount': int(packet.length),
            'byteperflow': byteperflow,
            'tot_kbps': float(packet.length) / 1000.0,
            'rx_kbps': float(packet.length) / 1000.0,
            'flows': 1,
            'bytecount': float(packet.length),
            'tot_dur': float(packet.frame_info.time_delta),
            'Protocol_ICMP': protocol_icmp,
            'Protocol_TCP': protocol_tcp,
            'Protocol_UDP': protocol_udp,
            'Protocol_HTTP': protocol_http,
            'Protocol_HTTPS': protocol_https,
            'Protocol_SSH': protocol_ssh,
            'Protocol_DHCP': protocol_dhcp,
            'Protocol_FTP': protocol_ftp,
            'Protocol_SMTP': protocol_smtp,
            'Protocol_POP3': protocol_pop3,
            'Protocol_IMAP': protocol_imap,
            'Protocol_DNS': protocol_dns,
            'src_ip': src_ip,  # Capture source IP address
            'dst_ip': dst_ip  ,
            'probability' : 0.0 # Capture destination IP address

        }

        return pd.DataFrame([features])
    except AttributeError:
        return None

def prepare_X_test(packets_list, drop_features):
   
    return None

def send_prediction(file_path):
    url = "http://127.0.0.1:8000/ddos-predictions/"
    with open(file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(url, files=files)
        if response.status_code == 200:
            print(f"Successfully sent {file_path} to API.")
        else:
            print(f"Failed to send {file_path} to API. Status code: {response.status_code}")

def make_predictions(X_test,X):
    logistic_regression_model = joblib.load('logistic_regression_model.pkl')
    svm_model = joblib.load('svm_model.pkl')
    knn_model = joblib.load('knn_model.pkl')
    decision_tree_model = joblib.load('decision_tree_model.pkl')
    random_forest_model = joblib.load('random_forest_model.pkl')

    scaler = StandardScaler()
    X_test_scaled = scaler.fit_transform(X_test)

    models = {
        'Logistic Regression': logistic_regression_model,
        'SVM': svm_model,
        'KNN': knn_model,
        'Decision Tree': decision_tree_model,
        'Random Forest': random_forest_model
    }
        # Open the CSV file for writing
    all_predictions = []



    # Collect predictions for each model
    for model_name, model in models.items():
        y_pred = model.predict(X_test_scaled)
        all_predictions.append(y_pred)
    # print(all_predictions, "-")
    # Transpose the list of predictions so that each row represents predictions from different models for each instance
    transposed_predictions = list(zip(*all_predictions))
    # print(transposed_predictions, "-")
    i = 0
    for row in transposed_predictions:
        row_sum = sum(row)
        
        avg = row_sum / 5
        X['probability'][i] = avg
        i+=1
        # print("keys: ", X.keys())
    
    # print("X  =", X)
        # return results
    with open('predictions.csv', mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=X.keys())  # Use the keys as headers
        writer.writeheader()  # Write the header
        for index, row in X.iterrows():
            # print(row)
            writer.writerow(row.to_dict())
    try:
        send_prediction("predictions.csv")
    except:
        print("could not connect to server")
def capture_packets(interface=None):

    try:
        subprocess.check_call(['sudo', 'apt', 'install', '-y', 'tshark'])
        print("tshark installed successfully.")
    except subprocess.CalledProcessError:
        print("Failed to install tshark. Please install it manually.")
    if interface is None:
        interface = get_active_interface()

    capture = pyshark.LiveCapture(interface=interface, tshark_path='/usr/bin/tshark')



    try:
        # print("here")
        # capture.sniff(timeout=60)
        while value:
            # print(value)
            packets_list = []
            if stop_event.is_set():
                break
            # print("c")
            count = 0
            # print(packets_list)
            for packet in capture:
                # print("h")

                if(count == 15):
                    break
                try:
                    processed_packet = preprocess_packet(packet)

                    if processed_packet is not None:
                        # print(processed_packet["dst_ip"])
                        # print(processed_packet["src_ip"])

                        if ":" in processed_packet["dst_ip"] or ":" in processed_packet["src_ip"]:
                            print("packet isn't correct")
                            continue
                            # print(processed_packet)
                        packets_list.append(processed_packet)
                        count+=1
                    # print(count)
                        
                except AttributeError as e:
                    print(f"Error processing packet: {e}")
                
            # X_test_scaled = prepare_X_test(packets_list, drop_features)
            if len(packets_list) >= 1:
                X_test = pd.concat(packets_list, ignore_index=True)
                X_test_scaled = X_test.drop(drop_features, axis=1, errors='ignore')
                X_test_scaled = X_test_scaled.reindex(columns=important_features, fill_value=0)

            if X_test_scaled is not None:
                results = make_predictions(X_test_scaled,X_test)
                # Write results to CSV
            time.sleep(10)
    except KeyboardInterrupt: 
        print("\nPacket capturing stopped.")
def start_capture():
    global thread
    if os.geteuid() != 0:
        root.withdraw()  # Hide the GUI before prompting for password
        password = simpledialog.askstring("Password", "Enter your sudo password and run again:", show='*')
        if password:
            try:
                subprocess.run(['sudo', '-S', sys.executable] + sys.argv, input=password.encode(), check=True)
            except subprocess.CalledProcessError:
                messagebox.showerror("Error", "Failed to run the script with sudo.")
            finally:
                root.destroy()  # Close the GUI after attempting to elevate privileges
        else:
            messagebox.showerror("Error", "No password provided. Unable to run with sudo.")
    elif not stop_event.is_set():
        global value 
        value = True
        stop_event.clear()
        thread = Thread(target=capture_packets)
        thread.start()

        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)

def stop_capture():
    global value
    value = False
    stop_event.set()
    if thread.is_alive():
        thread.join()  # Wait for the thread to finish
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)
    root.destroy()


def setup_gui():
    global root, start_button, stop_button, thread
    root = tk.Tk()
    root.title("Packet Capture Tool")

    start_button = tk.Button(root, text="Start Capture", command=start_capture)
    start_button.pack(pady=20)

    stop_button = tk.Button(root, text="Stop Capture", command=stop_capture, state=tk.DISABLED)
    stop_button.pack(pady=20)

    root.mainloop()

if __name__ == '__main__':
    setup_gui()
