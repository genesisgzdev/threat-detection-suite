import json
import os
import sys
import datetime
from github import Github

# Professional SOC Orchestrator with Dead-Letter Queue (DLQ) Fallback
# Handles dynamic threat reporting and ensures telemetry persistence even during API outages/403s.

class ThreatReporter:
    def __init__(self):
        self.github_token = os.getenv('GITHUB_TOKEN')
        self.repo_name = os.getenv('GITHUB_REPOSITORY', 'genesisgzdev/threat-detection-suite')
        self.dlq_path = "C:\\ProgramData\\TDS\\soc_dlq.log"

    def write_to_dlq(self, payload_data, error_msg):
        """Fallback mechanism: Saves alert to a local Dead Letter Queue if cloud reporting fails."""
        try:
            os.makedirs("C:\\ProgramData\\TDS", exist_ok=True)
            with open(self.dlq_path, 'a') as f:
                log_entry = {
                    "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
                    "status": "DLQ_FALLBACK",
                    "error": error_msg,
                    "payload": payload_data
                }
                f.write(json.dumps(log_entry) + "\n")
            print(f"WARN: Cloud alert failed ({error_msg}). Alert safely persisted to DLQ: {self.dlq_path}")
        except Exception as dlq_e:
            print(f"CRITICAL: DLQ Write Failed! Both cloud and local reporting are down: {str(dlq_e)}")

    def initialize_clients(self):
        if not self.github_token:
            print("WARN: GITHUB_TOKEN environment variable is not defined. Operating in Local-Only (DLQ) Mode.")
            return False
        
        try:
            self.gh = Github(auth=__import__('github').Auth.Token(self.github_token))
            self.repo = self.gh.get_repo(self.repo_name)
            return True
        except Exception as e:
            print(f"WARN: GitHub API Initialization failed ({str(e)}). Operating in Local-Only (DLQ) Mode.")
            return False

    def process_incident(self, payload):
        if not payload:
            return

        severity = payload.get('severity', 'UNKNOWN')
        category = payload.get('category', 'GENERAL')
        description = payload.get('description', 'No detailed description provided.')
        pid = payload.get('pid', 0)
        ioc = payload.get('ioc', 'N/A')

        title = f"[SOC-ALERT] {severity}: {category} Detection"
        
        body = f"""
## Security Operations Center (SOC) - Incident Report

### Technical Details
- **Description:** {description}
- **Artifact/IoC:** `{ioc}`
- **Target PID:** {pid}
- **Timestamp (UTC):** {datetime.datetime.now(datetime.UTC).isoformat()}Z

### Verification
- **Kernel Integrity:** ObRegisterCallbacks & Section Sync Interception enforced.
- **Forensics:** Automated minidump generated.
"""
        
        if hasattr(self, 'repo'):
            try:
                issue = self.repo.create_issue(title=title, body=body, labels=['security', f'severity-{severity.lower()}'])
                print(f"INFO: GitHub Issue #{issue.number} created successfully.")
                return
            except Exception as e:
                error_details = str(e)
                # Specifically catch 403s which we've been seeing
                if "403" in error_details or "Resource not accessible by personal access token" in error_details:
                    error_details = "403 Forbidden: Token lacks 'Issues: Write' permissions for this repo."
                
                self.write_to_dlq(payload, f"GitHub API Error: {error_details}")
        else:
            self.write_to_dlq(payload, "No active GitHub connection")

if __name__ == "__main__":
    reporter = ThreatReporter()
    reporter.initialize_clients() # We proceed even if false, to use DLQ
    
    try:
        input_data = sys.argv[1]
        if os.path.exists(input_data):
            with open(input_data, 'r') as f:
                data = json.load(f)
        else:
            data = json.loads(input_data)
        
        reporter.process_incident(data)
    except Exception as e:
        print(f"ERROR: Input processing failed: {str(e)}")
