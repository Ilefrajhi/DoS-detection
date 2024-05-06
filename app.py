from flask import Flask, render_template, request, jsonify
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Ensure that matplotlib backend is set before importing pyplot
import matplotlib.pyplot as plt
from io import BytesIO
import base64
import scapy.all as scapy
import csv
from collections import defaultdict
from datetime import datetime, timedelta
from flask import Flask, request
from flask import Flask, render_template, request, redirect, url_for
import subprocess

app = Flask(__name__)

# Route for handling the login page logic
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != 'admin' or request.form['password'] != 'admin':
            error = 'Invalid Credentials. Please try again.'
        else:
            return redirect(url_for('index'))
    return render_template('login.html', error=error)

@app.route('/result')
def result():
    # Any data you want to pass to the template can be provided here
    return render_template('result.html')

@app.route('/ping', methods=['POST'])
def ping():
    ip_address = request.form['ip_address']
    result = subprocess.call(['ping', '-c', '3', ip_address])
    if result == 0:
        message = "Your device is functioning properly."
    else:
        message = "Your device is down."
    return render_template('result.html', message=message)

matplotlib.use('Agg')

@app.route('/data')
def get_data():
    attack_data, ip_data = read_csv_data()
    return jsonify({"attacks": attack_data, "ip_counts": ip_data})

def read_csv_data():
    attack_data = defaultdict(int)
    ip_data = defaultdict(set)

    with open('wifi_dos.csv', mode='r') as file:
        reader = csv.reader(file)
        for row in reader:
            if len(row) >= 2:
                timestamp = row[0]
                if ',' in timestamp:  # Check if the timestamp contains time
                    time_only = timestamp.split(',')[1].split(':')[0]  # Extract minute
                    attack_data[time_only] += 1
                    ip = row[2]  # Assuming IP address is in the third column (index 2)
                    ip_data[time_only].add(ip)

    # Count unique IPs for each time period
    ip_counts = {time: len(ips) for time, ips in ip_data.items()}

    return attack_data, ip_counts

# Function to analyze the network and return connected IPs
def analyze_network():
    # Sniff packets to analyze the network
    packets = scapy.sniff(timeout=10)  # Sniff for 10 seconds, adjust as needed

    connected_ips = set()

    # Extract IP addresses from the sniffed packets
    for packet in packets:
        if scapy.IP in packet:
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            connected_ips.add(ip_src)
            connected_ips.add(ip_dst)

    return list(connected_ips)

# Update the analyze_network_route function
@app.route('/analyze_network')
def analyze_network_route():
    connected_ips = analyze_network()
    
    # Append the connected IP addresses to the CSV file
    with open('wifi_dos.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        if file.tell() == 0:
            writer.writerow(['Date', 'Time', 'Source IP'])
        now = datetime.now()
        date_time = now.strftime("%Y-%m-%d %H:%M:%S")
        for ip in connected_ips:
            writer.writerow([date_time.split()[0], date_time.split()[1], ip])
    
    return jsonify({"connected_ips": connected_ips})

@app.route('/index')
def index():
    # Read data from CSV file
    df = pd.read_csv('wifi_dos.csv')

    # Convert Date and Time columns to datetime
    df['DateTime'] = pd.to_datetime(df['Date'] + ' ' + df['Time'])

    # Group by Hour and Source IP, and count occurrences
    df['Hour'] = df['DateTime'].dt.hour  # Extract hour from DateTime
    grouped = df.groupby(['Hour', 'Source IP']).size().unstack(fill_value=0)

     # Plot Source IPs by Hour
    fig, ax = plt.subplots(figsize=(22, 5))  # Adjust size as needed
    grouped.plot(kind='line', marker='o', ax=ax)
    ax.set_xlabel('Hour of Day')
    ax.set_ylabel('Count')
    ax.set_title('Occurrences of Source IPs by Hour')
    ax.legend(title='Source IP', bbox_to_anchor=(1.05, 1), loc='upper left')
    ax.set_xticks(range(24))  # Set ticks for each hour of the day
    plt.tight_layout()

    # Convert Source IPs by Hour plot to base64 encoded string
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    source_ip_plot_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
    plt.close()

    # Identify DOS attacks (IPs occurring more than 1000 times in one hour)
    dos_attacks = df.groupby(['Hour', 'Source IP']).size().unstack(fill_value=0) > 10
    dos_attack_counts = dos_attacks.sum()

    # Calculate percentage of DOS attacks
    total_ips = len(grouped.columns)
    dos_attack_percentage = (dos_attack_counts > 0).sum() / total_ips * 100

    # Plot DOS Attacks Pie Chart
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.pie([total_ips - dos_attack_counts.sum(), dos_attack_counts.sum()], labels=['Normal IPs', 'DOS Attack IPs'], autopct='%1.1f%%', startangle=90)
    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
    ax.set_title('Percentage of DOS Attacks')

    # Convert DOS Attacks Pie Chart to base64 encoded string
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    dos_attack_plot_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
    plt.close()

    # Filter data for the last hour
    last_hour_df = df[df['DateTime'] >= df['DateTime'].max() - pd.Timedelta(hours=1)]

    # Group by minute and Source IP, and count occurrences
    last_hour_df['Minute'] = last_hour_df['DateTime'].dt.minute
    grouped_last_hour = last_hour_df.groupby(['Minute', 'Source IP']).size().unstack(fill_value=0)

    # Plot most occurring IPs in the last hour by minute
    fig, ax = plt.subplots(figsize=(5, 5))  # Adjust size as needed
    grouped_last_hour.sum().nlargest(10).plot(kind='bar', ax=ax)
    ax.set_xlabel('Source IP')
    ax.set_ylabel('Count')
    ax.set_title('Top 10 Most Occurring IPs in the Last Hour (by Minute)')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()

    # Convert plot to base64 encoded string
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    most_occuring_ips_plot_data = base64.b64encode(buffer.getvalue()).decode('utf-8')
    plt.close()

    return render_template('index.html', source_ip_plot_data=source_ip_plot_data, dos_attack_plot_data=dos_attack_plot_data, dos_attack_percentage=dos_attack_percentage, most_occuring_ips_plot_data=most_occuring_ips_plot_data)

if __name__ == '__main__':
    app.run(port=5004)  # Change 5001 to your desired port number
