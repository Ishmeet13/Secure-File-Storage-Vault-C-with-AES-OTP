# detect_anomalies.py

import pandas as pd
from datetime import datetime

# Load behavior log
try:
    df = pd.read_csv('behavior_log.csv', names=['user', 'hour', 'ip', 'timestamp'], engine='python')
except Exception as e:
    print(f"Error reading behavior_log.csv: {e}")
    exit(1)

# Safely convert 'timestamp' column to datetime
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

# Drop invalid rows
df.dropna(subset=['timestamp'], inplace=True)

# Extract useful features
df['hour'] = df['timestamp'].dt.hour
df['weekday'] = df['timestamp'].dt.weekday  # 0 = Monday, 6 = Sunday

# Define "off hours" as 12 AM - 5 AM and 10 PM - 11:59 PM
df['off_hours'] = df['hour'].apply(lambda x: x < 6 or x > 21)

# Group by user and mark suspicious patterns
anomalies = df[df['off_hours']].groupby('user').filter(lambda x: len(x) >= 2)

# Save anomaly entries
if not anomalies.empty:
    anomalies.to_csv('anomaly_log.csv', index=False)
    print("Anomalies detected and written to anomaly_log.csv")
else:
    # Create an empty file or clear old entries
    open('anomaly_log.csv', 'w').close()
    print("No anomalies detected.")
