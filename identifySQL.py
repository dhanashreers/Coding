# Python code to write code to read it and print out lines that seem to suggest SQLi attacks

import re

# Define patterns commonly seen in SQL injection attempts
SQLI_PATTERNS = [
    r"(?i)(union\s+select)",     # UNION SELECT keyword
    r"(?i)(or\s+1\s*=\s*1)",    # OR 1=1
    r"(?i)(and\s+1\s*=\s*1)",   # AND 1=1
    r"(?i)(\';\s*--)",          # ' -- for SQL comments
    r"(?i)(\';\s*#)",           # ' # for MySQL comments
    r"(?i)(sleep\(\d+\))",      # SQL sleep function
    r"(?i)(\bselect\b.*\bfrom\b)",  # SELECT FROM query
    r"(?i)(\bdrop\s+table\b)",  # DROP TABLE
    r"(?i)(\binsert\s+into\b)", # INSERT INTO
    r"(?i)(\bupdate\s+\w+\s+set\b)",  # UPDATE statement
    r"(?i)(\bdelete\s+from\b)", # DELETE FROM
    r"(?i)(\bshutdown\b)",      # Shutdown command
    r"(--)|(#)",                # Comment indicators
]

# Function to check if a log line matches any SQLi pattern
def is_sqli(line):
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, line):
            return True
    return False

# Function to read log file and print suspected SQLi lines
def detect_sqli_in_logs(log_file_path):
    try:
        with open(log_file_path, "r") as file:
            print(f"Analyzing log file: {log_file_path}\n")
            for line_num, line in enumerate(file, start=1):
                if is_sqli(line):
                    print(f"Suspicious activity detected on line {line_num}:\n{line.strip()}\n")
    except FileNotFoundError:
        print(f"File not found: {log_file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

# Replace with the path to your log file
log_file_path = "webapp_logs.txt"

# Run the detection
detect_sqli_in_logs(log_file_path)
