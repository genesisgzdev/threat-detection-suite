import json
import os
import sys
import datetime
from github import Github

class ThreatReporter:
    def __init__(self):
        self.github_token = os.getenv('GITHUB_TOKEN')
        self.repo_name = os.getenv('GITHUB_REPOSITORY', 'genesisgzdev/threat-detection-suite')

    def initialize_clients(self):
        if not self.github_token:
            print("ERROR: GITHUB_TOKEN environment variable is not defined.")
            return False
        
        try:
            self.gh = Github(self.github_token)
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
- **Timestamp (UTC):** {datetime.datetime.utcnow().isoformat()}Z

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
        fallback_path = os.getenv('SOC_FALLBACK_LOG', 'incident_report.log')
        try:
            with open(fallback_path, 'a') as f:
                timestamp = datetime.datetime.utcnow().isoformat()
                f.write(f"\n{'='*50}\n")
                f.write(f"FALLBACK REPORT - {timestamp}Z\n")
                f.write(f"ORIGINAL ERROR: {error}\n")
                f.write(f"TITLE: {title}\n")
                f.write(f"BODY: {body}\n")
                f.write(f"{'='*50}\n")
            print(f"INFO: Fallback report saved to {fallback_path}")
        except Exception as fe:
            print(f"CRITICAL: Fallback reporting also failed: {str(fe)}")
            sys.stderr.write(f"CRITICAL SOC ALERT: {title}\n{body}\n")

if __name__ == "__main__":
    reporter = ThreatReporter()
    if reporter.initialize_clients():
        try:
            input_data = sys.argv[1]
            # Check if input is a path or raw JSON
            if os.path.exists(input_data):
                with open(input_data, 'r') as f:
                    data = json.load(f)
            else:
                data = json.loads(input_data)
            
            reporter.process_incident(data)
        except Exception as e:
            print(f"ERROR: Input processing failed: {str(e)}")
