# Linux Privilege Escalation Automation Toolkit

Production-oriented, detection-only toolkit for Linux privilege escalation risk assessment.

## Repository Structure

- `src/privesc_toolkit/` - Core application package.
- `src/privesc_toolkit/checks/` - Detection modules (SUID, cron, sudo, services, kernel, permissions).
- `src/privesc_toolkit/analyzer/` - Risk scoring and finding correlation.
- `src/privesc_toolkit/reporter/` - Report export (JSON/Markdown/Text).
- `src/privesc_toolkit/collector/` - Command/system information collectors.
- `src/privesc_toolkit/config/` - Rules, signatures, and static risk data.
- `tests/` - Unit and integration tests.
- `docs/` - Project docs and architecture.
- `reports/` - Generated scan reports.

## 🚀 How to Run (Kali Linux / Target Machine)

The proper workflow is:
1. Run the scanner in the Linux terminal.
2. Generate the JSON report.
3. View the report in the Streamlit Dashboard.

### 🐧 Kali Linux Tutorial (Step-by-Step)

**Step 1: Clone the repository to your Kali VM**
Open your terminal in Kali Linux and run:
```bash
git clone https://github.com/aryancodesit/Linux-privilege-escalation-automation-toolkit.git
cd Linux-privilege-escalation-automation-toolkit
```

**Step 2: Run a Full Baseline Scan**
To run all privilege escalation checks (SUID, cron, sudo, services, etc.) and generate a report, use the following command:
```bash
python3 -m privesc_toolkit.main --scan baseline
```
*Note: This will automatically create a detailed JSON report and a Markdown report in the `reports/` directory.*

**Step 3: Run Specific Modules (Optional)**
If you only want to test specific vectors, you can run targeted scans:
- `python3 -m privesc_toolkit.main --scan suid-sgid`
- `python3 -m privesc_toolkit.main --scan permissions`
- `python3 -m privesc_toolkit.main --scan sudo`
- `python3 -m privesc_toolkit.main --scan cron`
- `python3 -m privesc_toolkit.main --scan kernel`

**Step 4: View the Results in the Dashboard**
Once the JSON reports are generated in the `reports/` directory, you can start the dashboard locally on Kali:
```bash
pip install -r requirements.txt
python3 -m streamlit run dashboard.py
```
This will open a beautiful interactive web interface at `http://localhost:8501` or you can just access the dashboard by clicking on the link shared in the description section where you can analyze the vulnerabilities!
