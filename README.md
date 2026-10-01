# Security Log Analyzer

An educational Python cybersecurity project that reads authentication logs, summarizes login activity, detects suspicious behavior, and saves security alerts to `alerts.txt`.

This project is designed for learning. It analyzes local example log files only and does not connect to real systems, scan networks, test passwords, or attack anything.

## Why Security Log Analysis Matters

Authentication logs show who tried to log in, when they tried, where they came from, and whether the login succeeded or failed. Security teams review this kind of data to spot suspicious patterns such as repeated failed passwords, attacks against many accounts, or a successful login after several failures.

## Features

- Parses login records from `sample_logs.txt`
- Skips blank, malformed, or unexpected log lines without crashing
- Counts total events, successful logins, failed logins, and unique IP addresses
- Groups failed and successful logins by IP address
- Counts usernames targeted by failed login attempts
- Detects possible brute-force attacks
- Detects possible password spraying
- Detects possible account compromise behavior
- Prints a readable console report
- Saves detected alerts to `alerts.txt`

## Attack Patterns Detected

### Brute-Force Attempts

A possible brute-force attack is detected when one IP address produces several failed login attempts in a short time window.

### Password Spraying

Password spraying is detected when one IP address fails to log in to several different usernames in a short time window. This can indicate an attacker trying one common password across many accounts.

### Suspicious Successful Login

A possible account compromise alert is created when an IP address has repeated failed attempts against a username and then successfully logs in to that same username shortly afterward.

The program describes these as possible or suspicious events because logs alone usually cannot prove intent.

## Project Structure

```text
security-log-analyzer/
    analyzer.py
    sample_logs.txt
    README.md
    LEARNING_NOTES.md
    alerts.txt
```

## Log Format

Each valid log line should contain five fields:

```text
YYYY-MM-DD HH:MM:SS EVENT_TYPE IP_ADDRESS USERNAME
```

Example:

```text
2026-09-23 10:01:05 LOGIN_FAILED 192.168.1.15 admin
2026-09-23 10:02:00 LOGIN_SUCCESS 192.168.1.20 subigya
```

Supported event types:

- `LOGIN_FAILED`
- `LOGIN_SUCCESS`

## How to Run

From the project folder, run:

```powershell
python analyzer.py
```

The program prints a report to the terminal and writes detected alerts to:

```text
alerts.txt
```

## How to Run Tests

This project uses Python's built-in `unittest` module, so no extra testing packages are required.

```powershell
python -m unittest discover
```

## Example Output

```text
==============================
SECURITY LOG ANALYSIS
==============================

Total events: 41
Successful logins: 12
Failed logins: 29
Unique IP addresses: 18

FAILED LOGIN ACTIVITY
192.168.1.15 -> 8
10.0.0.44 -> 5

SECURITY ALERTS

[HIGH] Possible brute-force attack
IP: 192.168.1.15
Failed attempts: 8
First attempt: 2026-09-23 10:01:05
Last attempt: 2026-09-23 10:02:11
Accounts targeted: admin, backup, guest, root, test
```

## Detection Thresholds

The thresholds are defined near the top of `analyzer.py` so they are easy to change:

```python
BRUTE_FORCE_FAILED_ATTEMPTS = 5
BRUTE_FORCE_WINDOW_SECONDS = 60

PASSWORD_SPRAY_UNIQUE_USERS = 4
PASSWORD_SPRAY_WINDOW_SECONDS = 120

SUSPICIOUS_SUCCESS_FAILED_ATTEMPTS = 3
SUSPICIOUS_SUCCESS_WINDOW_SECONDS = 180
```

## Severity Levels

The analyzer uses simple severity labels:

- `LOW`
- `MEDIUM`
- `HIGH`

Severity is based on easy-to-understand factors such as the number of failed attempts, how quickly they happened, how many usernames were targeted, and whether a successful login followed repeated failures.

## Limitations

- This is an educational project, not a production security tool.
- It only supports a simple text log format.
- It does not verify whether an IP address is actually malicious.
- It may produce false positives.
- It does not connect to live systems or real authentication services.
- It does not use advanced techniques such as machine learning or threat intelligence feeds.

## Future Improvements

- Add command-line options for custom log file paths
- Export reports as CSV or JSON
- Add automated unit tests for each detection function
- Support additional event types
- Track activity by username as well as by IP address
- Add configurable thresholds from a settings file
- Include timestamps in `alerts.txt` for when the report was generated
