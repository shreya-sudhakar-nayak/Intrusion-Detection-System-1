import random
from datetime import datetime, timedelta

def generate_log_file(file_name, num_entries):
    log_levels = ["INFO", "WARNING", "ALERT", "CRITICAL"]
    activities = [
        "User login: user123 from IP 192.168.1.10",
        "File accessed: /home/user123/document.txt",
        "User logout: user123",
        "Multiple failed login attempts from IP 192.168.1.11",
        "Unauthorized access to /etc/passwd",
        "Malware detected in /tmp/malicious_script.sh"
    ]
    
    current_time = datetime.now()
    
    with open(file_name, 'w') as f:
        for _ in range(num_entries):
            timestamp = current_time.strftime('%Y-%m-%d %H:%M:%S')
            log_level = random.choice(log_levels)
            activity = random.choice(activities)
            log_entry = f"{timestamp} {log_level} {activity}\n"
            f.write(log_entry)
            current_time += timedelta(seconds=random.randint(1, 10))

# Generate synthetic log files
generate_log_file("normal_activity.log", 50)
generate_log_file("intrusive_activity.log", 20)
