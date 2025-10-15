import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import json
import os
import subprocess
from datetime import datetime
import xml.etree.ElementTree as ET
import requests
import tempfile

class WebAppSecurityAutomation:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Application Security Automation - CI/CD Integration")
        self.root.geometry("1000x800")
        self.root.configure(bg='#2b2b2b')
        
        # Scan state
        self.is_scanning = False
        self.scan_thread = None
        self.scan_results = {}
        
        # Tool configurations
        self.security_tools = {
            "Burp Suite": {
                "command": "burp",
                "config": "--config-file=burp_config.json",
                "report_format": "html"
            },
            "OWASP ZAP": {
                "command": "zap-baseline.py",
                "config": "-t",
                "report_format": "xml"
            },
            "Nuclei": {
                "command": "nuclei",
                "config": "-u",
                "report_format": "json"
            },
            "Custom Script": {
                "command": "python",
                "config": "custom_scanner.py",
                "report_format": "json"
            }
        }
        
        self.create_widgets()

    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = tk.Label(main_frame, text="Web Application Security Automation", 
                              font=('Arial', 16, 'bold'), fg='white', bg='#2b2b2b')
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Target Configuration
        config_frame = ttk.LabelFrame(main_frame, text="Scan Configuration", padding="10")
        config_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # URL Target
        ttk.Label(config_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.url_var = tk.StringVar(value="https://example.com")
        ttk.Entry(config_frame, textvariable=self.url_var, width=40).grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # API Endpoint
        ttk.Label(config_frame, text="API Endpoints (comma-separated):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.api_var = tk.StringVar(value="/api/v1/users,/api/v1/admin")
        ttk.Entry(config_frame, textvariable=self.api_var, width=40).grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Security Tool Selection
        ttk.Label(config_frame, text="Security Tools:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.tools_var = tk.StringVar(value=["OWASP ZAP", "Nuclei"])
        tools_frame = ttk.Frame(config_frame)
        tools_frame.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        self.burp_var = tk.BooleanVar(value=False)
        self.zap_var = tk.BooleanVar(value=True)
        self.nuclei_var = tk.BooleanVar(value=True)
        self.custom_var = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(tools_frame, text="Burp Suite", variable=self.burp_var).pack(side=tk.LEFT)
        ttk.Checkbutton(tools_frame, text="OWASP ZAP", variable=self.zap_var).pack(side=tk.LEFT)
        ttk.Checkbutton(tools_frame, text="Nuclei", variable=self.nuclei_var).pack(side=tk.LEFT)
        ttk.Checkbutton(tools_frame, text="Custom Script", variable=self.custom_var).pack(side=tk.LEFT)
        
        # Scan Type
        ttk.Label(config_frame, text="Scan Type:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.scan_type_var = tk.StringVar(value="Full Security Scan")
        scan_combo = ttk.Combobox(config_frame, textvariable=self.scan_type_var,
                                 values=["Quick Scan", "Full Security Scan", "API Security Scan", 
                                        "Compliance Scan", "Custom Scan"],
                                 state="readonly", width=20)
        scan_combo.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # CI/CD Integration
        ttk.Label(config_frame, text="CI/CD Pipeline:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.cicd_var = tk.StringVar(value="Jenkins")
        cicd_combo = ttk.Combobox(config_frame, textvariable=self.cicd_var,
                                 values=["Jenkins", "GitHub Actions", "GitLab CI", "Azure DevOps", "Custom"],
                                 state="readonly", width=20)
        cicd_combo.grid(row=4, column=1, sticky=tk.W, pady=5)
        
        # Control Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=10)
        
        self.start_btn = ttk.Button(button_frame, text="Start Security Scan", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Generate CI/CD Config", command=self.generate_cicd_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export Report", command=self.export_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='determinate')
        self.progress.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        # Results Notebook
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        # Scan Log Tab
        log_frame = ttk.Frame(notebook, padding="5")
        self.scan_log = scrolledtext.ScrolledText(log_frame, height=20, width=100, bg='#1e1e1e', fg='white')
        self.scan_log.pack(fill=tk.BOTH, expand=True)
        notebook.add(log_frame, text="Scan Log")
        
        # Vulnerability Report Tab
        vuln_frame = ttk.Frame(notebook, padding="5")
        self.vuln_text = scrolledtext.ScrolledText(vuln_frame, height=20, width=100, bg='#1e1e1e', fg='white')
        self.vuln_text.pack(fill=tk.BOTH, expand=True)
        notebook.add(vuln_frame, text="Vulnerability Report")
        
        # CI/CD Configuration Tab
        cicd_frame = ttk.Frame(notebook, padding="5")
        self.cicd_text = scrolledtext.ScrolledText(cicd_frame, height=20, width=100, bg='#1e1e1e', fg='white')
        self.cicd_text.pack(fill=tk.BOTH, expand=True)
        notebook.add(cicd_frame, text="CI/CD Configuration")
        
        # Configure main frame grid weights
        main_frame.rowconfigure(4, weight=1)
        main_frame.columnconfigure(1, weight=1)

    def log_message(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        color_map = {
            "INFO": "white",
            "WARNING": "yellow",
            "ERROR": "red",
            "SUCCESS": "green",
            "SCAN": "cyan"
        }
        
        self.scan_log.insert(tk.END, f"[{timestamp}] {level}: {message}\n")
        self.scan_log.see(tk.END)
        
        # Color coding
        if level in color_map:
            self.scan_log.tag_configure(level, foreground=color_map[level])
            self.scan_log.tag_add(level, "end-2l", "end-1l")

    def start_scan(self):
        if self.is_scanning:
            return
            
        try:
            target_url = self.url_var.get()
            api_endpoints = self.api_var.get().split(',')
            scan_type = self.scan_type_var.get()
            cicd_platform = self.cicd_var.get()
            
            if not target_url.startswith(('http://', 'https://')):
                messagebox.showerror("Error", "Please enter a valid URL starting with http:// or https://")
                return
                
            self.is_scanning = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.progress['value'] = 0
            
            self.log_message(f"Starting {scan_type} for {target_url}", "SCAN")
            self.log_message(f"CI/CD Platform: {cicd_platform}", "INFO")
            
            # Start scan in separate thread
            self.scan_thread = threading.Thread(
                target=self.perform_security_scan,
                args=(target_url, api_endpoints, scan_type, cicd_platform),
                daemon=True
            )
            self.scan_thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start scan: {str(e)}")
            self.stop_scan()

    def stop_scan(self):
        self.is_scanning = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress['value'] = 0
        self.log_message("Security scan stopped", "INFO")

    def perform_security_scan(self, target_url, api_endpoints, scan_type, cicd_platform):
        """Main security scan function running in separate thread"""
        try:
            total_steps = 8  # Total steps in the scan process
            current_step = 0
            
            # Step 1: Environment Setup
            current_step += 1
            self.update_progress(current_step, total_steps, "Setting up scan environment...")
            self.log_message("Initializing security scan environment", "INFO")
            time.sleep(1)
            
            # Step 2: Tool Selection
            current_step += 1
            self.update_progress(current_step, total_steps, "Configuring security tools...")
            selected_tools = self.get_selected_tools()
            self.log_message(f"Selected tools: {', '.join(selected_tools)}", "INFO")
            
            # Step 3: Target Discovery
            current_step += 1
            self.update_progress(current_step, total_steps, "Discovering targets...")
            discovered_endpoints = self.discover_endpoints(target_url, api_endpoints)
            self.log_message(f"Discovered {len(discovered_endpoints)} endpoints to scan", "SUCCESS")
            
            # Step 4: Vulnerability Scanning
            current_step += 1
            self.update_progress(current_step, total_steps, "Running vulnerability scans...")
            scan_results = self.run_vulnerability_scans(target_url, discovered_endpoints, selected_tools)
            
            # Step 5: Results Analysis
            current_step += 1
            self.update_progress(current_step, total_steps, "Analyzing scan results...")
            self.analyze_scan_results(scan_results)
            
            # Step 6: Risk Assessment
            current_step += 1
            self.update_progress(current_step, total_steps, "Performing risk assessment...")
            risk_level = self.perform_risk_assessment(scan_results)
            
            # Step 7: CI/CD Integration
            current_step += 1
            self.update_progress(current_step, total_steps, "Generating CI/CD configuration...")
            self.generate_cicd_pipeline_config(cicd_platform, scan_results)
            
            # Step 8: Final Report
            current_step += 1
            self.update_progress(current_step, total_steps, "Generating final report...")
            self.generate_final_report(scan_results, risk_level)
            
            self.log_message("Security scan completed successfully!", "SUCCESS")
            
        except Exception as e:
            self.log_message(f"Scan error: {str(e)}", "ERROR")
        finally:
            self.is_scanning = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)

    def update_progress(self, current, total, message):
        progress_percent = (current / total) * 100
        self.progress['value'] = progress_percent
        self.log_message(message, "INFO")

    def get_selected_tools(self):
        """Get selected security tools"""
        selected = []
        if self.burp_var.get():
            selected.append("Burp Suite")
        if self.zap_var.get():
            selected.append("OWASP ZAP")
        if self.nuclei_var.get():
            selected.append("Nuclei")
        if self.custom_var.get():
            selected.append("Custom Script")
        return selected

    def discover_endpoints(self, target_url, api_endpoints):
        """Simulate endpoint discovery"""
        discovered = []
        
        # Common web endpoints
        common_endpoints = [
            "/", "/admin", "/login", "/logout", "/api", "/graphql",
            "/swagger.json", "/robots.txt", "/sitemap.xml"
        ]
        
        # Add user-provided API endpoints
        discovered.extend(api_endpoints)
        
        # Add common endpoints
        discovered.extend(common_endpoints)
        
        # Simulate discovery of additional endpoints
        for i in range(5):
            discovered.append(f"/api/v{random.randint(1,3)}/endpoint{i}")
            
        return list(set(discovered))  # Remove duplicates

    def run_vulnerability_scans(self, target_url, endpoints, tools):
        """Simulate running vulnerability scans with different tools"""
        import random
        
        scan_results = {
            "target": target_url,
            "scan_timestamp": datetime.now().isoformat(),
            "tools_used": tools,
            "vulnerabilities": [],
            "statistics": {
                "total_endpoints": len(endpoints),
                "scanned_endpoints": len(endpoints),
                "vulnerabilities_found": 0
            }
        }
        
        vulnerability_types = [
            {"type": "SQL Injection", "severity": "HIGH", "cvss": 8.5},
            {"type": "XSS", "severity": "MEDIUM", "cvss": 6.1},
            {"type": "CSRF", "severity": "MEDIUM", "cvss": 6.8},
            {"type": "Information Disclosure", "severity": "LOW", "cvss": 4.2},
            {"type": "Broken Authentication", "severity": "HIGH", "cvss": 8.2},
            {"type": "Security Misconfiguration", "severity": "MEDIUM", "cvss": 5.5},
            {"type": "Insecure Direct Object Reference", "severity": "MEDIUM", "cvss": 6.5}
        ]
        
        # Simulate finding vulnerabilities
        for endpoint in endpoints[:15]:  # Limit to first 15 endpoints for simulation
            if random.random() < 0.3:  # 30% chance of finding a vulnerability
                vuln = random.choice(vulnerability_types).copy()
                vuln["endpoint"] = endpoint
                vuln["tool"] = random.choice(tools)
                vuln["description"] = f"Potential {vuln['type']} vulnerability detected"
                vuln["recommendation"] = self.get_remediation_advice(vuln['type'])
                
                scan_results["vulnerabilities"].append(vuln)
                scan_results["statistics"]["vulnerabilities_found"] += 1
                
                self.log_message(f"Found {vuln['severity']} severity issue: {vuln['type']} at {endpoint}", "WARNING")
        
        return scan_results

    def get_remediation_advice(self, vuln_type):
        """Get remediation advice for vulnerability types"""
        advice_map = {
            "SQL Injection": "Use parameterized queries and input validation",
            "XSS": "Implement proper output encoding and Content Security Policy",
            "CSRF": "Add anti-CSRF tokens and validate origin headers",
            "Information Disclosure": "Review error messages and server configurations",
            "Broken Authentication": "Implement multi-factor authentication and strong password policies",
            "Security Misconfiguration": "Harden server configuration and remove default accounts",
            "Insecure Direct Object Reference": "Implement proper access controls and authorization checks"
        }
        return advice_map.get(vuln_type, "Review and implement security best practices")

    def analyze_scan_results(self, scan_results):
        """Analyze and display scan results"""
        self.vuln_text.delete(1.0, tk.END)
        
        report = f"""
SECURITY SCAN REPORT
====================
Target: {scan_results['target']}
Scan Date: {scan_results['scan_timestamp']}
Tools Used: {', '.join(scan_results['tools_used'])}

SUMMARY
-------
Total Endpoints Scanned: {scan_results['statistics']['total_endpoints']}
Vulnerabilities Found: {scan_results['statistics']['vulnerabilities_found']}

VULNERABILITIES
---------------
"""
        
        # Group by severity
        high_vulns = [v for v in scan_results['vulnerabilities'] if v['severity'] == 'HIGH']
        medium_vulns = [v for v in scan_results['vulnerabilities'] if v['severity'] == 'MEDIUM']
        low_vulns = [v for v in scan_results['vulnerabilities'] if v['severity'] == 'LOW']
        
        if high_vulns:
            report += "\nHIGH SEVERITY:\n"
            for vuln in high_vulns:
                report += f"• {vuln['type']} at {vuln['endpoint']} (CVSS: {vuln['cvss']})\n"
                report += f"  Tool: {vuln['tool']}\n"
                report += f"  Fix: {vuln['recommendation']}\n\n"
        
        if medium_vulns:
            report += "\nMEDIUM SEVERITY:\n"
            for vuln in medium_vulns:
                report += f"• {vuln['type']} at {vuln['endpoint']} (CVSS: {vuln['cvss']})\n"
                report += f"  Fix: {vuln['recommendation']}\n\n"
        
        if low_vulns:
            report += "\nLOW SEVERITY:\n"
            for vuln in low_vulns:
                report += f"• {vuln['type']} at {vuln['endpoint']} (CVSS: {vuln['cvss']})\n"
                report += f"  Fix: {vuln['recommendation']}\n\n"
        
        self.vuln_text.insert(tk.END, report)

    def perform_risk_assessment(self, scan_results):
        """Perform risk assessment based on scan results"""
        high_count = len([v for v in scan_results['vulnerabilities'] if v['severity'] == 'HIGH'])
        medium_count = len([v for v in scan_results['vulnerabilities'] if v['severity'] == 'MEDIUM'])
        
        if high_count > 0:
            risk_level = "CRITICAL"
        elif medium_count > 3:
            risk_level = "HIGH"
        elif medium_count > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        self.log_message(f"Risk Assessment: {risk_level} (High: {high_count}, Medium: {medium_count})", "WARNING")
        return risk_level

    def generate_cicd_pipeline_config(self, platform, scan_results):
        """Generate CI/CD pipeline configuration"""
        config_templates = {
            "Jenkins": self.generate_jenkins_config,
            "GitHub Actions": self.generate_github_actions_config,
            "GitLab CI": self.generate_gitlab_ci_config,
            "Azure DevOps": self.generate_azure_devops_config,
            "Custom": self.generate_custom_config
        }
        
        generator = config_templates.get(platform, self.generate_custom_config)
        config = generator(scan_results)
        
        self.cicd_text.delete(1.0, tk.END)
        self.cicd_text.insert(tk.END, config)
        
        self.log_message(f"Generated {platform} CI/CD configuration", "SUCCESS")

    def generate_jenkins_config(self, scan_results):
        """Generate Jenkins pipeline configuration"""
        return f"""// Jenkinsfile - Security Scanning Pipeline
pipeline {{
    agent any
    stages {{
        stage('Security Scan') {{
            steps {{
                script {{
                    // OWASP ZAP Scanning
                    sh 'zap-baseline.py -t {scan_results["target"]} -J zap-report.json'
                    
                    // Nuclei Scanning
                    sh 'nuclei -u {scan_results["target"]} -o nuclei-results.json'
                    
                    // Generate combined report
                    sh 'python security-report-generator.py'
                }}
            }}
            post {{
                always {{
                    // Archive security reports
                    archiveArtifacts artifacts: '*-report.json, security-report.html'
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: false,
                        keepAll: true,
                        reportDir: 'reports',
                        reportFiles: 'security-report.html',
                        reportName: 'Security Scan Report'
                    ])
                }}
                success {{
                    // Send success notification
                    emailext (
                        subject: "SECURITY SCAN PASSED: ${{env.JOB_NAME}}",
                        body: "Security scan completed successfully for {scan_results["target"]}",
                        to: "devops@company.com"
                    )
                }}
                failure {{
                    // Send failure notification for critical issues
                    emailext (
                        subject: "SECURITY SCAN FAILED: ${{env.JOB_NAME}}",
                        body: "Critical security issues found in {scan_results["target"]}",
                        to: "security-team@company.com"
                    )
                }}
            }}
        }}
    }}
}}
"""

    def generate_github_actions_config(self, scan_results):
        """Generate GitHub Actions workflow"""
        return f"""# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly scan

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v3

    - name: OWASP ZAP Scan
      uses: zaproxy/action-baseline@v0.7.0
      with:
        target: '{scan_results["target"]}'
        rules_file_name: '.zap/rules.tsv'
        cmd_options: '-a'

    - name: Nuclei Scan
      uses: projectdiscovery/nuclei-action@main
      with:
        target: '{scan_results["target"]}'
        templates: 'cves,security-misconfigurations'

    - name: Upload SARIF report
      uses: github/codeql-action/upload-sarif@v2
      if: always()
      with:
        sarif_file: 'results.sarif'

    - name: Security Report
      uses: madhead/security-report@v1
      if: always()
"""

    def generate_gitlab_ci_config(self, scan_results):
        """Generate GitLab CI configuration"""
        return f"""# .gitlab-ci.yml
stages:
  - security

zap_scan:
  stage: security
  image: owasp/zap2docker-stable
  script:
    - zap-baseline.py -t {scan_results["target"]} -g gen.conf -J zap-report.json
  artifacts:
    paths:
      - zap-report.json
    when: always

nuclei_scan:
  stage: security
  image: projectdiscovery/nuclei:latest
  script:
    - nuclei -u {scan_results["target"]} -o nuclei-results.json
  artifacts:
    paths:
      - nuclei-results.json
    when: always

security_report:
  stage: security
  image: python:3.9
  script:
    - pip install -r requirements.txt
    - python generate_security_report.py
  artifacts:
    paths:
      - security-report.html
    when: always
  only:
    - main
    - develop
"""

    def generate_azure_devops_config(self, scan_results):
        """Generate Azure DevOps pipeline"""
        return f"""# azure-pipelines.yml
trigger:
  branches:
    include:
    - main
    - develop

pool:
  vmImage: 'ubuntu-latest'

stages:
- stage: Security
  jobs:
  - job: SecurityScan
    steps:
    - task: Bash@3
      displayName: 'OWASP ZAP Scan'
      inputs:
        targetType: 'inline'
        script: |
          docker run -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable \
          zap-baseline.py -t {scan_results["target"]} -J zap-report.json

    - task: Bash@3
      displayName: 'Nuclei Scan'
      inputs:
        targetType: 'inline'
        script: |
          docker run -v $(pwd):/results projectdiscovery/nuclei:latest \
          -u {scan_results["target"]} -o /results/nuclei-results.json

    - task: PublishBuildArtifacts@1
      displayName: 'Publish Security Reports'
      inputs:
        PathtoPublish: '$(System.DefaultWorkingDirectory)'
        ArtifactName: 'SecurityReports'
        publishLocation: 'Container'
"""

    def generate_custom_config(self, scan_results):
        """Generate custom CI/CD configuration"""
        return f"""# Custom CI/CD Security Pipeline
# Target: {scan_results["target"]}
# Scan Date: {scan_results["scan_timestamp"]}

SECURITY_SCAN_CONFIG = {{
    "target_url": "{scan_results["target"]}",
    "tools": {json.dumps(scan_results["tools_used"], indent=2)},
    "scan_schedule": "daily",
    "fail_on_critical": true,
    "report_formats": ["html", "json", "pdf"],
    "notifications": {{
        "email": "security-team@company.com",
        "slack": "#security-alerts",
        "jira": "SECURITY"
    }}
}}

# Implementation Steps:
1. Integrate security tools into build pipeline
2. Configure automated scanning on code changes
3. Set up quality gates based on security findings
4. Implement security reporting and dashboards
5. Establish incident response procedures
"""

    def generate_cicd_config(self):
        """Generate CI/CD configuration on demand"""
        if not hasattr(self, 'last_scan_results'):
            messagebox.showinfo("Info", "Please run a security scan first to generate CI/CD configuration")
            return
            
        platform = self.cicd_var.get()
        self.generate_cicd_pipeline_config(platform, self.last_scan_results)

    def generate_final_report(self, scan_results, risk_level):
        """Generate final security report"""
        self.last_scan_results = scan_results
        
        report = f"""
FINAL SECURITY ASSESSMENT REPORT
================================

Application: {scan_results['target']}
Assessment Date: {scan_results['scan_timestamp']}
Overall Risk Level: {risk_level}

EXECUTIVE SUMMARY
-----------------
- Total Vulnerabilities: {scan_results['statistics']['vulnerabilities_found']}
- High Severity Issues: {len([v for v in scan_results['vulnerabilities'] if v['severity'] == 'HIGH'])}
- Security Tools Used: {', '.join(scan_results['tools_used'])}

RECOMMENDATIONS
---------------
1. Address all HIGH severity issues immediately
2. Implement automated security testing in CI/CD
3. Conduct regular security training for developers
4. Establish security code review processes
5. Monitor for new vulnerabilities continuously

CI/CD INTEGRATION
-----------------
Security scanning has been successfully integrated into the {self.cicd_var.get()} pipeline.
Scans will run automatically on code changes and scheduled intervals.
"""
        self.log_message("Final security report generated", "SUCCESS")

    def export_report(self):
        """Export scan results to file"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("HTML files", "*.html"), ("All files", "*.*")]
            )
            
            if filename and hasattr(self, 'last_scan_results'):
                with open(filename, 'w') as f:
                    json.dump(self.last_scan_results, f, indent=2)
                
                self.log_message(f"Report exported to {filename}", "SUCCESS")
            else:
                messagebox.showinfo("Info", "Please run a security scan first to export results")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export report: {str(e)}")

    def clear_log(self):
        """Clear all log windows"""
        self.scan_log.delete(1.0, tk.END)
        self.vuln_text.delete(1.0, tk.END)
        self.cicd_text.delete(1.0, tk.END)
        self.log_message("Logs cleared", "INFO")

# Import random for simulation purposes
import random

def main():
    root = tk.Tk()
    app = WebAppSecurityAutomation(root)
    root.mainloop()

if __name__ == "__main__":
    main()