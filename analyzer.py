# Counter helps count repeated things easily, like failed logins per IP.
# defaultdict(list) automatically gives us an empty list when a new key appears.
# datetime works with real dates/times, and timedelta represents a time difference.
from collections import Counter, defaultdict
from datetime import datetime, timedelta


# These are constants: values we plan to keep the same while the program runs.
# Uppercase names are a Python convention for constants.
LOG_FILE = "sample_logs.txt"
ALERTS_FILE = "alerts.txt"

# Detection thresholds are grouped here so we can easily tune the rules later.
# Detection thresholds are kept near the top so they are easy to tune.
BRUTE_FORCE_FAILED_ATTEMPTS = 5
BRUTE_FORCE_WINDOW_SECONDS = 60

PASSWORD_SPRAY_UNIQUE_USERS = 4
PASSWORD_SPRAY_WINDOW_SECONDS = 120

SUSPICIOUS_SUCCESS_FAILED_ATTEMPTS = 3
SUSPICIOUS_SUCCESS_WINDOW_SECONDS = 180

# Only these two event types are accepted as valid login events.
VALID_EVENT_TYPES = {"LOGIN_FAILED", "LOGIN_SUCCESS"}


# This function takes ONE raw log line and turns it into structured data.
# It returns (entry, warning). If the line is valid, warning is None.
def parse_log_line(line, line_number):
    """Parse one log line into a dictionary, or return an error message."""
# strip() removes spaces/newlines from the beginning and end of the line.
    stripped_line = line.strip()

# If the line is empty after stripping, skip it quietly.
    if not stripped_line:
        return None, None

# split() separates the line by spaces into 5 expected pieces.
    parts = stripped_line.split()
# Every valid log line should have exactly:
# date, time, event type, IP address, username.
    if len(parts) != 5:
        return None, f"Line {line_number}: malformed record skipped"

# Unpack the 5 pieces into clear variable names.
    date_text, time_text, event_type, ip_address, username = parts

# Reject events that are not LOGIN_FAILED or LOGIN_SUCCESS.
    if event_type not in VALID_EVENT_TYPES:
        return None, f"Line {line_number}: unexpected event type '{event_type}' skipped"

# Convert the date + time text into a real datetime object.
# This is important because later we compare how many seconds passed between attempts.
    try:
        timestamp = datetime.strptime(f"{date_text} {time_text}", "%Y-%m-%d %H:%M:%S")
# If the date/time format is bad, datetime.strptime() raises ValueError.
    except ValueError:
        return None, f"Line {line_number}: invalid date or time skipped"

# Store the parsed information in a dictionary so each field has a name.
    return {
        "date": date_text,
        "time": time_text,
        "timestamp": timestamp,
        "event_type": event_type,
        "ip_address": ip_address,
        "username": username,
    }, None


# This function reads the whole log file and parses it one line at a time.
def read_logs(file_path):
    """Read a log file and return valid entries plus skipped-line warnings."""
# entries stores valid log events; warnings stores bad-line messages.
    entries = []
    warnings = []

# try/except lets the program handle a missing file without crashing.
    try:
# with open(...) automatically closes the file after we are done reading it.
        with open(file_path, "r", encoding="utf-8") as log_file:
# enumerate(..., start=1) gives us both the line number and the line text.
            for line_number, line in enumerate(log_file, start=1):
# Send each raw line to parse_log_line().
                entry, warning = parse_log_line(line, line_number)

# Valid entries go into entries; parser warnings go into warnings.
                if entry:
                    entries.append(entry)
                elif warning:
                    warnings.append(warning)
# This runs only if the log file does not exist.
    except FileNotFoundError:
        warnings.append(f"Log file not found: {file_path}")

# Return both good data and warnings to the rest of the program.
    return entries, warnings


# This function calculates the main summary statistics for the report.
def calculate_statistics(entries):
    """Calculate summary statistics from parsed log entries."""
# Counter works like a dictionary made for counting.
# Example: failed_by_ip['192.168.1.15'] += 1
    failed_by_ip = Counter()
    success_by_ip = Counter()
    failed_usernames = Counter()
# A set stores unique values only, so duplicate IPs are automatically ignored.
    unique_ip_addresses = set()

# Go through every parsed log entry.
    for entry in entries:
        ip_address = entry["ip_address"]
        username = entry["username"]
# Add the IP to the set of unique IP addresses.
        unique_ip_addresses.add(ip_address)

# Count failures separately from successful logins.
        if entry["event_type"] == "LOGIN_FAILED":
            failed_by_ip[ip_address] += 1
            failed_usernames[username] += 1
        elif entry["event_type"] == "LOGIN_SUCCESS":
            success_by_ip[ip_address] += 1

# Return all calculated statistics together in one dictionary.
    return {
        "total_events": len(entries),
        "successful_logins": sum(success_by_ip.values()),
        "failed_logins": sum(failed_by_ip.values()),
        "failed_by_ip": failed_by_ip,
        "success_by_ip": success_by_ip,
        "failed_usernames": failed_usernames,
        "unique_ip_addresses": unique_ip_addresses,
    }


# This helper groups ONLY failed login entries by IP address.
def group_failed_entries_by_ip(entries):
    """Group failed login entries by IP address."""
# defaultdict(list) means a new IP automatically starts with an empty list.
    failed_by_ip = defaultdict(list)

# Add each failed login entry to the list belonging to its IP.
    for entry in entries:
        if entry["event_type"] == "LOGIN_FAILED":
            failed_by_ip[entry["ip_address"]].append(entry)

# Sort each IP's failures by timestamp so time-window checks work correctly.
    for ip_address in failed_by_ip:
# lambda here means: use each item's timestamp as the sorting value.
        failed_by_ip[ip_address].sort(key=lambda item: item["timestamp"])

    return failed_by_ip


# Decide how serious a brute-force alert should be.
def choose_brute_force_severity(failed_attempts, first_time, last_time):
    """Decide severity for brute-force behavior using simple, readable rules."""
# Subtract two datetime values, then convert the difference to seconds.
    time_span = (last_time - first_time).total_seconds()

# More attempts or a very short time span makes the alert more serious.
    # More attempts in a short time means the behavior is more urgent.
    if failed_attempts >= 8 or time_span <= 30:
        return "HIGH"
    if failed_attempts >= 5:
        return "MEDIUM"
    return "LOW"


# Decide password-spraying severity based on account spread and attempt count.
def choose_password_spray_severity(unique_user_count, failed_attempts):
    """Decide severity for password spraying based on account spread."""
    # Password spraying is more serious when many accounts are touched.
    if unique_user_count >= 6 or failed_attempts >= 8:
        return "HIGH"
    if unique_user_count >= PASSWORD_SPRAY_UNIQUE_USERS:
        return "MEDIUM"
    return "LOW"


# Look for many failed attempts from the same IP inside a short time window.
def detect_brute_force(entries):
    """Find IPs with many failed logins inside a short time window."""
# alerts will hold every brute-force alert we find.
    alerts = []
# First organize failures by IP so each IP can be analyzed separately.
    failed_by_ip = group_failed_entries_by_ip(entries)
# Convert 60 seconds into a timedelta so it can be compared with datetimes.
    window = timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS)

# Analyze one IP and its failed attempts at a time.
    for ip_address, failures in failed_by_ip.items():
# Try each failure as a possible starting point of a suspicious time window.
        for start_index, first_entry in enumerate(failures):
# Build a list of failures that happened within the allowed window.
# This is a list comprehension: a short way to build a new list.
            window_entries = [
                entry
                for entry in failures[start_index:]
                if entry["timestamp"] - first_entry["timestamp"] <= window
            ]

# If enough failures happened inside the window, create one brute-force alert.
            if len(window_entries) >= BRUTE_FORCE_FAILED_ATTEMPTS:
                last_entry = failures[-1]
# A set removes duplicate usernames, sorted() makes the output predictable.
                usernames = sorted({entry["username"] for entry in failures})

# Store the alert as a dictionary so the report code can format it later.
                alerts.append({
                    "type": "Possible brute-force attack",
                    "severity": choose_brute_force_severity(
                        len(failures),
                        first_entry["timestamp"],
                        window_entries[-1]["timestamp"],
                    ),
                    "ip_address": ip_address,
                    "failed_attempts": len(failures),
                    "first_attempt": failures[0]["timestamp"],
                    "last_attempt": last_entry["timestamp"],
                    "usernames": usernames,
                })
# break prevents creating multiple brute-force alerts for the same IP.
                break

    return alerts


# Password spraying means one source tries several different usernames quickly.
def detect_password_spraying(entries):
    """Find IPs trying several usernames in a short time period."""
    alerts = []
# Reuse the same failed-login grouping helper.
    failed_by_ip = group_failed_entries_by_ip(entries)
    window = timedelta(seconds=PASSWORD_SPRAY_WINDOW_SECONDS)

# Check each IP separately.
    for ip_address, failures in failed_by_ip.items():
# Try each failed attempt as the beginning of a possible spray window.
        for start_index, first_entry in enumerate(failures):
            window_entries = [
                entry
                for entry in failures[start_index:]
                if entry["timestamp"] - first_entry["timestamp"] <= window
            ]
# Get the unique usernames targeted inside this time window.
            usernames = sorted({entry["username"] for entry in window_entries})

# If enough different accounts were targeted, create a spraying alert.
            if len(usernames) >= PASSWORD_SPRAY_UNIQUE_USERS:
                last_entry = window_entries[-1]

                alerts.append({
                    "type": "Possible password spraying",
                    "severity": choose_password_spray_severity(
                        len(usernames),
                        len(window_entries),
                    ),
                    "ip_address": ip_address,
                    "failed_attempts": len(window_entries),
                    "first_attempt": first_entry["timestamp"],
                    "last_attempt": last_entry["timestamp"],
                    "usernames": usernames,
                })
# One alert per IP is enough, so stop checking more windows for that IP.
                break

    return alerts


# Look for repeated failures followed by a successful login to the SAME account.
def detect_suspicious_success(entries):
    """Find repeated failures followed by a successful login to the same account."""
    alerts = []
# Key = (IP address, username).
# Each key stores all login events for that exact IP + account combination.
    entries_by_ip_and_user = defaultdict(list)
    window = timedelta(seconds=SUSPICIOUS_SUCCESS_WINDOW_SECONDS)

# Group every event using the pair (IP, username).
    for entry in entries:
# A tuple is used as the dictionary key because we need BOTH values together.
        key = (entry["ip_address"], entry["username"])
        entries_by_ip_and_user[key].append(entry)

# Now analyze each IP + username pair separately.
    for (ip_address, username), related_entries in entries_by_ip_and_user.items():
# Sort by time so earlier failures appear before later successes.
        related_entries.sort(key=lambda item: item["timestamp"])

# Look through the events and only react when we reach a successful login.
        for entry in related_entries:
# continue skips the rest of this loop iteration for non-success events.
            if entry["event_type"] != "LOGIN_SUCCESS":
                continue

# Find failed attempts that happened shortly BEFORE this successful login.
            failed_before_success = [
                previous_entry
                for previous_entry in related_entries
                if previous_entry["event_type"] == "LOGIN_FAILED"
# The time difference must be greater than 0 and inside the suspicious window.
                and timedelta(seconds=0) < entry["timestamp"] - previous_entry["timestamp"] <= window
            ]

# If enough failures happened before the success, flag it as suspicious.
            if len(failed_before_success) >= SUSPICIOUS_SUCCESS_FAILED_ATTEMPTS:
                alerts.append({
                    "type": "Possible account compromise",
                    "severity": "HIGH",
                    "ip_address": ip_address,
                    "username": username,
                    "failed_attempts": len(failed_before_success),
                    "success_time": entry["timestamp"],
                })
                break
# Stop after creating one suspicious-success alert for this IP + username pair.

    return alerts


# Convert a datetime object back into readable text for the report.
def format_timestamp(timestamp):
    """Format a datetime for reports."""
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


# Format a Counter so the most common item appears first.
def format_counter(counter):
    """Format a Counter from highest count to lowest count."""
# If there is nothing to display, show 'None' instead of an empty section.
    if not counter:
        return ["None"]

# most_common() returns Counter items from highest count to lowest.
    return [
        f"{item} -> {count}"
        for item, count in counter.most_common()
    ]


# Build the full human-readable report as a list of text lines.
def generate_report(statistics, alerts, warnings):
    """Create the console report text."""
# Starting report header and basic statistics.
    report_lines = [
        "==============================",
        "SECURITY LOG ANALYSIS",
        "==============================",
        "",
        f"Total events: {statistics['total_events']}",
        f"Successful logins: {statistics['successful_logins']}",
        f"Failed logins: {statistics['failed_logins']}",
        f"Unique IP addresses: {len(statistics['unique_ip_addresses'])}",
        "",
        "FAILED LOGIN ACTIVITY",
    ]

# extend() adds multiple strings to report_lines at once.
    report_lines.extend(format_counter(statistics["failed_by_ip"]))
    report_lines.extend(["", "SUCCESSFUL LOGIN ACTIVITY"])
    report_lines.extend(format_counter(statistics["success_by_ip"]))
    report_lines.extend(["", "MOST FREQUENTLY TARGETED USERNAMES"])
    report_lines.extend(format_counter(statistics["failed_usernames"]))

# Only show the WARNINGS section if there are warnings.
    if warnings:
        report_lines.extend(["", "WARNINGS"])
        report_lines.extend(warnings)

# Add the SECURITY ALERTS section after the summary information.
    report_lines.extend(["", "SECURITY ALERTS"])

# If nothing suspicious was detected, say that clearly.
    if not alerts:
        report_lines.append("No security alerts detected.")
    else:
# Format each alert and add its lines to the report.
        for alert in alerts:
            report_lines.extend(format_alert(alert))

# Join every report line together using newline characters.
    return "\n".join(report_lines)


# Turn one alert dictionary into readable report lines.
def format_alert(alert):
    """Format one alert for the report and alerts file."""
    lines = [
        "",
        f"[{alert['severity']}] {alert['type']}",
        f"IP: {alert['ip_address']}",
    ]

# Account-compromise alerts contain different fields from brute-force/spray alerts.
    if alert["type"] == "Possible account compromise":
        lines.extend([
            f"Username: {alert['username']}",
            f"Failed attempts before success: {alert['failed_attempts']}",
            f"Successful login time: {format_timestamp(alert['success_time'])}",
        ])
    else:
        lines.extend([
            f"Failed attempts: {alert['failed_attempts']}",
            f"First attempt: {format_timestamp(alert['first_attempt'])}",
            f"Last attempt: {format_timestamp(alert['last_attempt'])}",
            f"Accounts targeted: {', '.join(alert['usernames'])}",
        ])

    return lines


# Save only the security alerts into alerts.txt.
def save_alerts(alerts, file_path):
    """Save only the detected alerts to a text file."""
# 'w' means write mode, so the old alerts file is replaced each run.
    with open(file_path, "w", encoding="utf-8") as alerts_file:
# If there are no alerts, still write a clear message to the file.
        if not alerts:
            alerts_file.write("No security alerts detected.\n")
            return

# Write every alert with a blank line between alerts.
        for alert in alerts:
            alerts_file.write("\n".join(format_alert(alert)).strip())
            alerts_file.write("\n\n")


# main() controls the overall order of the program.
def main():
# Step 1: read and parse the logs.
    entries, warnings = read_logs(LOG_FILE)
# Step 2: calculate summary statistics.
    statistics = calculate_statistics(entries)

# Step 3: collect alerts from each detection method.
    alerts = []
    alerts.extend(detect_brute_force(entries))
    alerts.extend(detect_password_spraying(entries))
    alerts.extend(detect_suspicious_success(entries))

# Step 4: build and print the report.
    report = generate_report(statistics, alerts, warnings)
    print(report)
# Step 5: save the alerts to alerts.txt.
    save_alerts(alerts, ALERTS_FILE)


# This makes main() run only when analyzer.py is executed directly.
# It will NOT automatically run when analyzer.py is imported by the tests.
if __name__ == "__main__":
    main()
