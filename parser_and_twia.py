import time
import threading
import re
import json
import requests
import queue
from datetime import datetime

OLLAMA_URL = "http://100.79.39.61:11434/api/generate" # URL of the Ollama model API endpoint
OLLAMA_MODEL = "mistral" # Model name to use for analysis

log_queue = queue.Queue() # Thread-safe queue to hold parsed logs before analysis    

# Continuously read new lines appended to a file (like tail -f)
def tail_f(filepath):
    with open(filepath, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line
            
# Parse an Apache access log line
def parse_apache_access(line):
    ip_match = re.search(r'\[VULN_SITE\]\s+(\d+\.\d+\.\d+\.\d+)', line)
    if not ip_match:
        return None
    ip = ip_match.group(1)

    m = re.search(r'\[([0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} [+\-0-9]+)\] '
                  r'"(\S+) (\S+) \S+" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"', line)
    if not m:
        return None
    timestamp, method, path, status, size, referrer, user_agent = m.groups()

    return {
        "log_type": "apache-access",
        "ip": ip,
        "timestamp": timestamp,
        "method": method,
        "path": path,
        "status": int(status),
        "size": int(size) if size.isdigit() else 0,
        "referrer": referrer,
        "user_agent": user_agent
    }
    
# Parse a MariaDB log line
def parse_mariadb(line):
    try:
        if "mariadb" not in line:
            return None
        parts = line.split("mariadb", 1)[1].strip()
        parts = parts.replace("#011", "\t")
        fields = parts.split("\t")
        if len(fields) < 2:
            return None
        thread_id = fields[0].strip()
        cmd_msg = "\t".join(fields[1:]).strip()
        cmd_split = cmd_msg.split(None, 1)
        command = cmd_split[0] if len(cmd_split) > 0 else ""
        message = cmd_split[1] if len(cmd_split) > 1 else ""
        timestamp = line.split(" vuln mariadb")[0].strip()
        return {
            "log_type": "mariadb",
            "timestamp": timestamp,
            "thread_id": int(thread_id) if thread_id.isdigit() else 0,
            "command": command,
            "message": message
        }
    except Exception:
        return None

# Continuously process logs from queue, analyze with model, and print results
def analyze_logs_from_queue():
    prompt_template = (
        "You are a cybersecurity log analysis expert.\n"
        "Given one log entry as JSON, respond ONLY with a single JSON object with these keys:\n"
        "- log: the original log entry as received\n"
        "- attack: boolean, true if attack detected, false otherwise\n"
        "- attack_probability: float between 0.0 and 1.0\n"
        "If and only if attack is true, add:\n"
        "- attack_type: string describing the attack\n"
        "- advice: string with security advice\n"
        "If attack is false, DO NOT include 'attack_type' and 'advice', include them only if attack is true.\n"
        "DO NOT include any text, explanation, or code — ONLY the JSON object."
    )

    while True:
        log = log_queue.get()
        if log is None:
            break

        try:
            prompt = f"{prompt_template}\n\n{json.dumps(log)}"

            response = requests.post(OLLAMA_URL, json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            })

            if response.status_code != 200:
                print(f"[ERROR] Model response status: {response.status_code}")
                continue

            raw_response = response.json().get("response", "")

            try:
                result = json.loads(raw_response)
            except json.JSONDecodeError as e:
                print(f"[ERROR] JSON decode error from model response: {e}")
                print(f"Raw response:\n{raw_response}")
                continue

            prefix = "[ALERT]" if result.get("attack") else "[INFO]"
            print(prefix, json.dumps(result, indent=2))

        except Exception as e:
            print("[ERROR] analyze_log exception:", e)

        finally:
            log_queue.task_done()

# Continuously read logs from a file, parse them, and add to queue
def process_log(filepath, parser_func):
    print(f"[DEBUG] Start monitoring {filepath}")
    for line in tail_f(filepath):
        parsed = parser_func(line)
        if parsed:
            log_queue.put(parsed)
        else:
            print(f"[DEBUG] Unparsed line from {filepath}: {line.strip()}")

if __name__ == "__main__":
    files_and_parsers = {
        "/var/log/remote/vuln/apache-access.log": parse_apache_access,
        "/var/log/remote/vuln/mariadb.log": parse_mariadb,
    }

    # Start thread for analyzing logs
    thread_analyze = threading.Thread(target=analyze_logs_from_queue, daemon=True)
    thread_analyze.start()

    threads = []
    # Start threads for each log file
    for file, parser in files_and_parsers.items():
        t = threading.Thread(target=process_log, args=(file, parser), daemon=True)
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping...")
        log_queue.put(None)
        thread_analyze.join()
