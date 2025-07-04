import os
from collections import Counter
from datetime import datetime

# --- Configuration ---
# Define keywords to look for in logs that might indicate security events.
SECURITY_KEYWORDS = [
    "failed login", "authentication failure", "access denied", "error",
    "unauthorized", "malware", "virus", "attack", "injection", "scan",
    "bruteforce", "suspicious", "alert", "warning", "critical", "denied"
]

# Define common log patterns for different event types (simplified for this example).
# In a real scenario, you'd use more robust regex or a log parsing library.
LOGIN_FAILURE_PATTERN = re.compile(r'(?i)(failed|failure|denied)\s+login|authentication\s+(failed|failure|denied)')
ACCESS_DENIED_PATTERN = re.compile(r'(?i)access\s+denied')
ERROR_PATTERN = re.compile(r'(?i)error|exception')

# --- Helper Functions ---

def analyze_log_file(file_path: str):
    """
    Reads a log file line by line, identifies security-related events,
    and provides a summary.

    Args:
        file_path (str): The path to the log file.
    """
    if not os.path.exists(file_path):
        print(f"Error: File not found at '{file_path}'")
        return

    print(f"\nAnalyzing log file: {file_path}")
    print("-" * 50)

    total_lines = 0
    security_events = []
    event_types_count = Counter() # To count occurrences of different event types

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                total_lines += 1
                line_lower = line.lower()

                # Check for general security keywords
                is_security_event = False
                for keyword in SECURITY_KEYWORDS:
                    if keyword in line_lower:
                        security_events.append((line_num, line.strip()))
                        is_security_event = True
                        break # Only add once per line if multiple keywords exist

                # Check for specific patterns and categorize
                if LOGIN_FAILURE_PATTERN.search(line_lower):
                    event_types_count['Login Failures'] += 1
                if ACCESS_DENIED_PATTERN.search(line_lower):
                    event_types_count['Access Denied'] += 1
                if ERROR_PATTERN.search(line_lower):
                    event_types_count['Errors'] += 1
                # Add more specific patterns here as needed

    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        return

    print(f"Total lines processed: {total_lines}")
    print(f"Total potential security events found: {len(security_events)}")
    print("\n--- Summary of Event Types ---")
    if event_types_count:
        for event_type, count in event_types_count.items():
            print(f"- {event_type}: {count}")
    else:
        print("No specific event patterns identified.")

    print("\n--- Detailed Security Events ---")
    if security_events:
        for line_num, event_line in security_events:
            print(f"Line {line_num}: {event_line}")
    else:
        print("No lines matched general security keywords.")

    print("-" * 50)
    print("Log analysis complete.")

def create_sample_log_file(filename="sample.log"):
    """
    Creates a sample log file for testing purposes.
    """
    print(f"Creating a sample log file: {filename}")
    sample_content = [
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} INFO: User 'john_doe' logged in successfully from 192.168.1.100",
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} WARNING: Failed login attempt for user 'admin' from 203.0.113.5",
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ERROR: Database connection lost. Retrying...",
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} INFO: System update completed.",
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} CRITICAL: Unauthorized access attempt detected on port 22 from 10.0.0.50",
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ALERT: Possible SQL injection detected in request from 172.16.0.1",
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} INFO: User 'jane_smith' logged out.",
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} WARNING: Authentication failure for user 'testuser' from 198.51.100.20",
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ERROR: File not found: /var/log/app.log",
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} INFO: Service 'web_server' restarted successfully."
    ]
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for line in sample_content:
                f.write(line + '\n')
        print(f"Sample log file '{filename}' created successfully.")
    except Exception as e:
        print(f"Error creating sample log file: {e}")

def main():
    """
    Main function for the log analyzer.
    Allows user to specify a log file or create a sample one.
    """
    print("-" * 50)
    print("Basic Log File Analyzer")
    print("-" * 50)

    sample_filename = "sample.log"
    create_sample_log_file(sample_filename) # Always create a sample file for easy testing

    while True:
        choice = input(f"\nEnter log file path (or 's' for sample.log, 'q' to quit): ").lower()
        if choice == 'q':
            break
        elif choice == 's':
            log_file_path = sample_filename
        else:
            log_file_path = choice

        analyze_log_file(log_file_path)
        print("\n" + "=" * 50)

if __name__ == "__main__":
    import re # Import re here as it's used by patterns outside main()
    main()
