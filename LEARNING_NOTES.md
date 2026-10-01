# Learning Notes

These notes explain the main Python and cybersecurity ideas used in this project.

## Python Concepts

### Opening and Reading Files

Python can open a text file with `open()`. In this project, `read_logs()` opens `sample_logs.txt` and reads it one line at a time.

Using `with open(...) as file:` is helpful because Python automatically closes the file when the block is finished.

### Strings and `split()`

Each log line starts as one string, such as:

```text
2026-09-23 10:01:05 LOGIN_FAILED 192.168.1.15 admin
```

The `split()` method separates that string into pieces wherever there is whitespace:

```python
["2026-09-23", "10:01:05", "LOGIN_FAILED", "192.168.1.15", "admin"]
```

That makes it easier to access the date, time, event type, IP address, and username.

### Lists

A list stores multiple values in order. This project uses lists for parsed log entries, alert messages, and report lines.

Lists are useful when order matters, such as reading log events from oldest to newest.

### Dictionaries

A dictionary stores key-value pairs. In this project, each parsed log entry is stored as a dictionary:

```python
{
    "timestamp": datetime_object,
    "event_type": "LOGIN_FAILED",
    "ip_address": "192.168.1.15",
    "username": "admin",
}
```

Dictionaries make the code easier to read because `entry["ip_address"]` is clearer than remembering that the IP address is item number 3 in a list.

### Sets

A set stores unique values. This project uses sets to count unique IP addresses and unique usernames targeted by an IP address.

Sets are useful when duplicates should only count once.

### Loops

Loops repeat work. This project uses loops to read every log line, count every event, and check every IP address for suspicious activity.

### Conditionals

Conditionals let the program make decisions with `if`, `elif`, and `else`.

For example, the analyzer checks whether an event is `LOGIN_FAILED` or `LOGIN_SUCCESS` before deciding how to count it.

### Functions

Functions group related code into named blocks. This makes the project easier to understand and test.

Examples from this project include:

- `parse_log_line()`
- `read_logs()`
- `calculate_statistics()`
- `detect_brute_force()`
- `detect_password_spraying()`
- `detect_suspicious_success()`
- `generate_report()`
- `save_alerts()`

### `datetime`

The `datetime` module lets Python understand dates and times. This matters because security detections often depend on timing.

For example, five failed logins in one minute are more suspicious than five failed logins spread across several days.

### Sorting

Sorting puts values in a predictable order. This project sorts failed logins by timestamp before checking for short time-window attacks.

### Counting and Grouping Data

Security analysis often means grouping many events into useful summaries.

This project uses:

- `Counter` to count failed logins per IP address
- `defaultdict(list)` to group failed login entries by IP address
- Sets to count unique usernames and IP addresses

### Exceptions

Exceptions are errors Python can catch and handle. This project catches `FileNotFoundError` so the program can show a warning instead of crashing if the log file is missing.

It also catches invalid dates with `ValueError`.

### Why Dictionaries Are Useful for Grouping by IP Address

IP addresses are natural dictionary keys because each IP can point to a list or count of related events.

For example:

```python
{
    "192.168.1.15": 8,
    "10.0.0.44": 5,
}
```

This makes it easy to answer questions like, "Which IP address had the most failed logins?"

## Cybersecurity Concepts

### Authentication Logs

Authentication logs record login activity. A basic authentication log usually includes:

- Timestamp
- Whether the login succeeded or failed
- Source IP address
- Username

These logs help defenders investigate suspicious access attempts.

### Failed Login Attempts

A failed login means someone tried to log in but did not provide valid credentials.

One failed login can be normal. Many failed logins in a short time can be suspicious.

### Brute-Force Attacks

A brute-force attack happens when an attacker repeatedly guesses passwords for one or more accounts.

In this project, an IP address with at least 5 failed login attempts within 60 seconds triggers a possible brute-force alert.

### Password Spraying

Password spraying is when an attacker tries a small number of common passwords across many different usernames.

This can avoid lockouts that might happen when attacking one account many times.

In this project, an IP address failing against 4 or more unique usernames within 120 seconds triggers a possible password spraying alert.

### Suspicious Login Behavior

Repeated failures followed by a successful login can be suspicious because it may mean the correct password was eventually guessed.

This project creates a possible account compromise alert when the same IP has at least 3 failed attempts against the same username and then succeeds within 180 seconds.

### False Positives

A false positive is an alert that looks suspicious but has a harmless explanation.

For example, a real user might mistype a password several times and then finally log in successfully.

### Detection Thresholds

A threshold is the point where the program decides activity should become an alert.

Lower thresholds catch more suspicious activity but may create more false positives. Higher thresholds create fewer alerts but may miss some attacks.

This is why the thresholds in `analyzer.py` are placed near the top of the file and are easy to change.
