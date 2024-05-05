
import csv
from datetime import datetime
import matplotlib.pyplot as plt

def draw_dashboard(csv_file):
    dates = []
    source_ips = []

    # Read the CSV file and extract data
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            # Assuming the first column is the date and the second is the source IP
            if len(row) == 2:
                dates.append(datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S'))
                source_ips.append(row[1])

    # Create a time series plot of occurrences over time
    plt.figure(figsize=(10, 6))
    plt.hist(dates, bins=20, edgecolor='black')
    plt.title('Occurrences Over Time')
    plt.xlabel('Date')
    plt.ylabel('Occurrences')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('static/images/occurrences_over_time.png')

    # Create a pie chart of 'Source IP' frequencies
    plt.figure(figsize=(8, 6))
    plt.pie([source_ips.count(ip) for ip in set(source_ips)], labels=set(source_ips), autopct='%1.1f%%')
    plt.title('Source IP Distribution')
    plt.savefig('static/images/ip_distribution.png')
