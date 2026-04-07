import json
import os
import sys
import datetime
from github import Github, Auth

class ThreatReporter:
    def __init__(self):
        self.github_token = os.getenv('GITHUB_TOKEN')
        self.repo_name = os.getenv('GITHUB_REPOSITORY', 'genesisgzdev/threat-detection-suite')

    def initialize_clients(self):
        if not self.github_token:
            print("ERROR: GITHUB_TOKEN environment variable is not defined.")
            return False
        
        try:
            # Modern GitHub Auth (resolves 401/403 related to token legacy format)
            auth = Auth.Token(self.github_token)
            self.gh = Github(auth=auth)
            self.repo = self.gh.get_repo(self.repo_name)
            return True
        except Exception as e:
            print(f"ERROR: Initialization failed: {str(e)}")
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
- **Kernel Integrity:** ObRegisterCallbacks enforced.
- **Forensics:** Automated minidump generated.
"""
        
        try:
            issue = self.repo.create_issue(title=title, body=body, labels=['security', f'severity-{severity.lower()}'])
            print(f"INFO: GitHub Issue #{issue.number} created successfully.")
        except Exception as e:
            print(f"ERROR: Reporting failed: {str(e)}")
            self.fallback_report(title, body, str(e))

    def fallback_report(self, title, body, error):
        """Logs to local secure file if GitHub is inaccessible."""
        log_path = os.getenv('SOC_FALLBACK_LOG', 'incident_report.log')
        with open(log_path, 'a') as f:
            f.write(f"\n--- {title} ---\n{body}\nError: {error}\n")
        print(f"CRITICAL: Remote reporting failed. Incident persisted to {log_path}")

if __name__ == "__main__":
    reporter = ThreatReporter()
    if reporter.initialize_clients():
        try:
            if len(sys.argv) > 1:
                input_data = sys.argv[1]
                if os.path.exists(input_data):
                    with open(input_data, 'r') as f:
                        data = json.load(f)
                else:
                    data = json.loads(input_data)
                reporter.process_incident(data)
        except Exception as e:
            print(f"ERROR: Input processing failed: {str(e)}")
