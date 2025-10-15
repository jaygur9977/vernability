
        // Mock data
        const mockData = {
            "target": "shopka.example",
            "scan_time": "2025-10-09T19:00:00+05:30",
            "scan_duration": "2 minutes 45 seconds",
            "findings": [
                {
                    "id": "F-001",
                    "title": "Outdated WP Payments plugin",
                    "severity": "Critical",
                    "cve": "CVE-2021-73492",
                    "csvv": 9.1,
                    "description": "Plugin allows arbitrary file upload via 'amount' parameter. This vulnerability could allow an attacker to upload malicious files to the server and potentially execute arbitrary code.",
                    "component": "WordPress plugin wp-payments v1.2",
                    "evidence": "HTTP response shows /wp-content/plugins/wp-payments/pay.php with vulnerable param 'amount'",
                    "references": [
                        "https://nvd.nist.gov/vuln/detail/CVE-2021-89263",
                        "https://exploit-db.com/exploit/12345"
                    ],
                    "raw_output": "[nuclei] matched template wp-payments-vuln - /pay.php - param 'amount'...\n[nuclei] [CRITICAL] Arbitrary file upload vulnerability detected\n[nuclei] Payload sent: malicious_file.exe via amount parameter\n[nuclei] Server responded with 200 OK - file uploaded successfully",
                    "attack_path": {
                        "steps": [
                            "Attacker identifies vulnerable plugin",
                            "Exploits file upload vulnerability",
                            "Uploads malicious file to server",
                            "Gains remote code execution",
                            "Accesses sensitive data"
                        ],
                        "impact": "Complete system compromise"
                    }
                },
                {
                    "id": "F-002",
                    "title": "Open SSH (port 22) with weak password policy",
                    "severity": "High",
                    "cve": null,
                    "csvv": 7.4,
                    "description": "SSH accepts password auth; weak policy detected. This could allow brute force attacks to gain unauthorized access to the server.",
                    "component": "OpenSSH 7.2p2",
                    "evidence": "SSH allows password login; login attempts not rate-limited.",
                    "references": [],
                    "raw_output": "[nmap] 22/tcp open ssh OpenSSH 7.2p2\n[hydra] SSH brute force successful with weak credentials: admin:admin123\n[scan] No rate limiting detected - 1000 attempts per minute allowed",
                    "attack_path": {
                        "steps": [
                            "Attacker scans for open SSH port",
                            "Identifies weak password policy",
                            "Performs brute force attack",
                            "Gains SSH access",
                            "Escalates privileges"
                        ],
                        "impact": "Server access and potential privilege escalation"
                    }
                },
                {
                    "id": "F-003",
                    "title": "SQL Injection in login form",
                    "severity": "High",
                    "cve": "CVE-2020-58723",
                    "csvv": 8.2,
                    "description": "Login form vulnerable to SQL injection attacks. Attackers could bypass authentication or extract sensitive data from the database.",
                    "component": "Custom login script login.php",
                    "evidence": "SQL errors returned when injecting special characters in username field.",
                    "references": [
                        "https://nvd.nist.gov/vuln/detail/CVE-2020-69284"
                    ],
                    "raw_output": "[sqlmap] testing login.php\n[sqlmap] parameter 'username' is vulnerable\n[sqlmap] payload: admin' OR '1'='1\n[sqlmap] database type: MySQL\n[sqlmap] current user: root@localhost",
                    "attack_path": {
                        "steps": [
                            "Attacker identifies SQL injection point",
                            "Exploits injection to bypass authentication",
                            "Extracts database information",
                            "Accesses sensitive user data",
                            "Potentially modifies database content"
                        ],
                        "impact": "Data breach and unauthorized access"
                    }
                },
                {
                    "id": "F-004",
                    "title": "Missing security headers",
                    "severity": "Medium",
                    "cve": null,
                    "csvv": 5.3,
                    "description": "Missing X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy headers. This could expose the application to clickjacking and MIME-type sniffing attacks.",
                    "component": "Web server configuration",
                    "evidence": "HTTP response headers analysis shows missing security headers.",
                    "references": [],
                    "raw_output": "[securityheaders] X-Content-Type-Options: missing\n[securityheaders] X-Frame-Options: missing\n[securityheaders] Content-Security-Policy: missing\n[securityheaders] Strict-Transport-Security: missing",
                    "attack_path": {
                        "steps": [
                            "Attacker identifies missing security headers",
                            "Exploits clickjacking vulnerability",
                            "Tricks user into performing actions",
                            "Potentially steals sensitive information"
                        ],
                        "impact": "User data exposure and session hijacking"
                    }
                }
            ]
        };

        // DOM Elements
        const themeToggle = document.getElementById('themeToggle');
        const targetOptions = document.querySelectorAll('.target-option');
        const domainInput = document.getElementById('domainInput');
        const ipInput = document.getElementById('ipInput');
        const uploadZone = document.getElementById('uploadZone');
        const fileInput = document.getElementById('fileInput');
        const fileName = document.getElementById('fileName');
        const authCheckbox = document.getElementById('authCheckbox');
        const startScanBtn = document.getElementById('startScanBtn');
        const passwordModal = document.getElementById('passwordModal');
        const scannerName = document.getElementById('scannerName');
        const passwordInput = document.getElementById('passwordInput');
        const authenticateBtn = document.getElementById('authenticateBtn');
        const scanModal = document.getElementById('scanModal');
        const scannerDisplayName = document.getElementById('scannerDisplayName');
        const scanTargetDisplay = document.getElementById('scanTargetDisplay');
        const progressFill = document.getElementById('progressFill');
        const progressPercent = document.getElementById('progressPercent');
        const scanLogs = document.getElementById('scanLogs');
        const reportSection = document.getElementById('reportSection');
        const reportTarget = document.getElementById('reportTarget');
        const reportDate = document.getElementById('reportDate');
        const reportDuration = document.getElementById('reportDuration');
        const reportScanner = document.getElementById('reportScanner');
        const criticalCount = document.getElementById('criticalCount');
        const highCount = document.getElementById('highCount');
        const mediumCount = document.getElementById('mediumCount');
        const lowCount = document.getElementById('lowCount');
        const findingsList = document.getElementById('findingsList');
        const attackPathGraph = document.getElementById('attackPathGraph');
        const chatMessages = document.getElementById('chatMessages');
        const chatInput = document.getElementById('chatInput');
        const sendChatBtn = document.getElementById('sendChatBtn');
        const attackPathModal = document.getElementById('attackPathModal');
        const evidenceModal = document.getElementById('evidenceModal');
        const evidenceContent = document.getElementById('evidenceContent');
        const copyEvidenceBtn = document.getElementById('copyEvidenceBtn');
        const closeModalButtons = document.querySelectorAll('.close-modal');
        const exportPdfBtn = document.getElementById('exportPdfBtn');
        const rescanBtn = document.getElementById('rescanBtn');
        const toast = document.getElementById('toast');
        const toastMessage = document.getElementById('toastMessage');

        // Scanner Animation
        const documentScanner = document.querySelector('.scan-object.document');
        const websiteScanner = document.querySelector('.scan-object.website');
        
        // Initialize scanner animation
        function initScannerAnimation() {
            let isDocumentActive = true;
            
            setInterval(() => {
                if (isDocumentActive) {
                    documentScanner.classList.remove('active');
                    websiteScanner.classList.add('active');
                } else {
                    websiteScanner.classList.remove('active');
                    documentScanner.classList.add('active');
                }
                
                isDocumentActive = !isDocumentActive;
            }, 6000);
        }

        // Theme Toggle
        themeToggle.addEventListener('click', () => {
            const currentTheme = document.body.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            document.body.setAttribute('data-theme', newTheme);
            
            // Update icon
            const icon = themeToggle.querySelector('i');
            icon.className = newTheme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
        });

        // Target Option Selection
        targetOptions.forEach(option => {
            option.addEventListener('click', () => {
                targetOptions.forEach(opt => opt.classList.remove('active'));
                option.classList.add('active');
                
                const type = option.getAttribute('data-type');
                
                domainInput.style.display = type === 'domain' ? 'block' : 'none';
                ipInput.style.display = type === 'ip' ? 'block' : 'none';
                uploadZone.style.display = type === 'upload' ? 'block' : 'none';
                
                checkScanButtonState();
            });
        });

        // File Upload Handling
        uploadZone.addEventListener('click', () => {
            fileInput.click();
        });

        uploadZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadZone.classList.add('dragover');
        });

        uploadZone.addEventListener('dragleave', () => {
            uploadZone.classList.remove('dragover');
        });

        uploadZone.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadZone.classList.remove('dragover');
            
            if (e.dataTransfer.files.length) {
                handleFileSelection(e.dataTransfer.files[0]);
            }
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length) {
                handleFileSelection(e.target.files[0]);
            }
        });

        function handleFileSelection(file) {
            if (file && file.name.endsWith('.zip')) {
                fileName.textContent = `Selected: ${file.name}`;
                checkScanButtonState();
            } else {
                alert('Please select a ZIP file');
                fileInput.value = '';
                fileName.textContent = '';
            }
        }

        // Input validation
        domainInput.addEventListener('input', checkScanButtonState);
        ipInput.addEventListener('input', checkScanButtonState);

        // Authorization Checkbox
        authCheckbox.addEventListener('change', checkScanButtonState);

        function checkScanButtonState() {
            const targetType = document.querySelector('.target-option.active').getAttribute('data-type');
            let isValid = false;
            
            if (targetType === 'domain') {
                isValid = domainInput.value.trim() !== '';
            } else if (targetType === 'ip') {
                isValid = ipInput.value.trim() !== '';
            } else if (targetType === 'upload') {
                isValid = fileInput.files.length > 0;
            }
            
            startScanBtn.disabled = !(isValid && authCheckbox.checked);
        }

        // Start Scan - Show Password Modal
        startScanBtn.addEventListener('click', () => {
            passwordModal.classList.add('active');
        });

        // Authenticate and Start Scan
        authenticateBtn.addEventListener('click', () => {
            const name = scannerName.value.trim();
            const password = passwordInput.value;
            
            if (!name) {
                showToast("Please enter your name", "error");
                return;
            }
            
            if (password !== "admin123") {
                showToast("Invalid passcode. Please try again.", "error");
                return;
            }
            
            // Close password modal and start scan
            passwordModal.classList.remove('active');
            startScan(name);
        });

        function startScan(scannerName) {
            // Show scan modal
            scanModal.classList.add('active');
            
            // Set scanner name and target
            scannerDisplayName.textContent = scannerName;
            scanTargetDisplay.textContent = domainInput.value || ipInput.value || "Uploaded file";
            
            // Clear previous logs
            scanLogs.innerHTML = '<div class="log-entry"><span class="log-time">[19:00:00]</span><span>Initializing scanner...</span></div>';
            
            // Reset progress
            progressFill.style.width = '0%';
            progressPercent.textContent = '0%';
            
            // Simulate scan progress
            const logs = [
                {time: "19:00:01", message: "Loading vulnerability databases..."},
                {time: "19:00:02", message: "Establishing connection to target..."},
                {time: "19:00:04", message: "Performing port scan..."},
                {time: "19:00:07", message: "Port 22: Open - SSH service detected"},
                {time: "19:00:09", message: "Port 80: Open - HTTP service detected"},
                {time: "19:00:11", message: "Port 443: Open - HTTPS service detected"},
                {time: "19:00:15", message: "Starting web application scan..."},
                {time: "19:00:20", message: "WordPress installation detected"},
                {time: "19:00:25", message: "Scanning plugins for vulnerabilities..."},
                {time: "19:00:32", message: "Vulnerability detected: Outdated WP Payments plugin"},
                {time: "19:00:40", message: "Testing for SQL injection vulnerabilities..."},
                {time: "19:00:48", message: "Vulnerability detected: SQL Injection in login form"},
                {time: "19:00:55", message: "Checking security headers..."},
                {time: "19:01:02", message: "Vulnerability detected: Missing security headers"},
                {time: "19:01:10", message: "Testing SSH security..."},
                {time: "19:01:18", message: "Vulnerability detected: Weak SSH password policy"},
                {time: "19:01:25", message: "Generating comprehensive report..."},
                {time: "19:01:35", message: "Scan completed successfully!"}
            ];
            
            let index = 0;
            const logInterval = setInterval(() => {
                if (index < logs.length) {
                    const logEntry = document.createElement('div');
                    logEntry.className = 'log-entry new';
                    logEntry.innerHTML = `<span class="log-time">[${logs[index].time}]</span><span>${logs[index].message}</span>`;
                    scanLogs.appendChild(logEntry);
                    scanLogs.scrollTop = scanLogs.scrollHeight;
                    
                    // Update progress
                    const progress = ((index + 1) / logs.length) * 100;
                    progressFill.style.width = `${progress}%`;
                    progressPercent.textContent = `${Math.round(progress)}%`;
                    
                    index++;
                } else {
                    clearInterval(logInterval);
                    
                    // Close modal and show report after a short delay
                    setTimeout(() => {
                        scanModal.classList.remove('active');
                        reportSection.classList.add('active');
                        renderFindings(scannerName);
                        
                        // Scroll to report section
                        reportSection.scrollIntoView({ behavior: 'smooth' });
                    }, 1500);
                }
            }, 800);
        }

        // Render Findings
        function renderFindings(scannerName) {
            // Update report metadata
            reportTarget.textContent = mockData.target;
            reportDate.textContent = new Date(mockData.scan_time).toLocaleDateString('en-US', { 
                year: 'numeric', 
                month: 'long', 
                day: 'numeric' 
            });
            reportDuration.textContent = mockData.scan_duration;
            reportScanner.textContent = scannerName;
            
            // Count vulnerabilities by severity
            const severityCounts = {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0
            };
            
            mockData.findings.forEach(finding => {
                severityCounts[finding.severity.toLowerCase()]++;
            });
            
            criticalCount.textContent = severityCounts.critical;
            highCount.textContent = severityCounts.high;
            mediumCount.textContent = severityCounts.medium;
            lowCount.textContent = severityCounts.low;
            
            // Render findings
            findingsList.innerHTML = '';
            
            mockData.findings.forEach(finding => {
                const findingCard = document.createElement('div');
                findingCard.className = `finding-card ${finding.severity.toLowerCase()}`;
                
                const severityClass = `severity-${finding.severity.toLowerCase()}`;
                
                findingCard.innerHTML = `
                    <div class="finding-header">
                        <div>
                            <div class="finding-id">${finding.id}</div>
                            <h3 class="finding-title">${finding.title}</h3>
                        </div>
                        <span class="severity-pill ${severityClass}">${finding.severity}</span>
                    </div>
                    
                    <div class="finding-details">
                        ${finding.cve ? `<div class="cve-id">${finding.cve}</div>` : ''}
                        <div class="csvv-badge">CSVV: ${finding.csvv}</div>
                    </div>
                    
                    <p class="finding-description">${finding.description}</p>
                    
                    <div class="finding-component">Affected: ${finding.component}</div>
                    
                    ${finding.references.length > 0 ? `
                    <div class="finding-references">
                        ${finding.references.map(ref => 
                            `<a href="#" class="reference-link" target="_blank">${ref.includes('nvd') ? 'NVD' : 'ExploitDB'}</a>`
                        ).join('')}
                    </div>
                    ` : ''}
                    
                    <div class="finding-actions">
                        <button class="action-btn attack-path-btn" data-finding-id="${finding.id}">
                            <i class="fas fa-project-diagram"></i>
                            Attack Path
                        </button>
                        <button class="action-btn evidence-btn" data-finding-id="${finding.id}">
                            <i class="fas fa-search"></i>
                            View Evidence
                        </button>
                    </div>
                `;
                
                findingsList.appendChild(findingCard);
            });
            
            // Add event listeners to action buttons
            document.querySelectorAll('.attack-path-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const findingId = e.currentTarget.getAttribute('data-finding-id');
                    showAttackPath(findingId);
                });
            });
            
            document.querySelectorAll('.evidence-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const findingId = e.currentTarget.getAttribute('data-finding-id');
                    showEvidence(findingId);
                });
            });
            
            // Render attack path graph
            renderAttackPathGraph();
        }

        // Render Attack Path Graph
        function renderAttackPathGraph() {
            attackPathGraph.innerHTML = '';
            
            // Create nodes for each vulnerability
            const vulnerabilities = mockData.findings;
            const colors = {
                critical: 'var(--danger)',
                high: 'var(--warning)',
                medium: 'var(--info)',
                low: 'var(--success)'
            };
            
            // Create internet node
            const internetNode = document.createElement('div');
            internetNode.className = 'graph-node';
            internetNode.textContent = 'Internet';
            internetNode.style.backgroundColor = 'var(--secondary)';
            internetNode.style.top = '50px';
            internetNode.style.left = '50px';
            internetNode.setAttribute('data-tooltip', 'External attacker with network access');
            attackPathGraph.appendChild(internetNode);
            
            // Create service node
            const serviceNode = document.createElement('div');
            serviceNode.className = 'graph-node';
            serviceNode.textContent = 'Web Service';
            serviceNode.style.backgroundColor = 'var(--accent)';
            serviceNode.style.color = 'var(--primary)';
            serviceNode.style.top = '50px';
            serviceNode.style.right = '50px';
            serviceNode.setAttribute('data-tooltip', 'Vulnerable service exposed to the internet');
            attackPathGraph.appendChild(serviceNode);
            
            // Create vulnerability nodes
            vulnerabilities.forEach((vuln, index) => {
                const vulnNode = document.createElement('div');
                vulnNode.className = 'graph-node';
                vulnNode.textContent = vuln.id;
                vulnNode.style.backgroundColor = colors[vuln.severity.toLowerCase()];
                vulnNode.style.top = `${120 + index * 50}px`;
                vulnNode.style.left = '50%';
                vulnNode.style.transform = 'translateX(-50%)';
                vulnNode.setAttribute('data-tooltip', `${vuln.title} (${vuln.severity}) - ${vuln.description.substring(0, 100)}...`);
                vulnNode.setAttribute('data-finding-id', vuln.id);
                attackPathGraph.appendChild(vulnNode);
                
                // Add click event to show attack path
                vulnNode.addEventListener('click', () => {
                    showAttackPath(vuln.id);
                });
            });
            
            // Create database node
            const dbNode = document.createElement('div');
            dbNode.className = 'graph-node';
            dbNode.textContent = 'Database';
            dbNode.style.backgroundColor = 'var(--success)';
            dbNode.style.bottom = '50px';
            dbNode.style.left = '50%';
            dbNode.style.transform = 'translateX(-50%)';
            dbNode.setAttribute('data-tooltip', 'Sensitive data storage');
            attackPathGraph.appendChild(dbNode);
            
            // Create connections
            createGraphConnection(internetNode, serviceNode);
            
            vulnerabilities.forEach((vuln, index) => {
                const vulnNode = attackPathGraph.querySelector(`[data-finding-id="${vuln.id}"]`);
                createGraphConnection(serviceNode, vulnNode);
                createGraphConnection(vulnNode, dbNode);
            });
            
            // Add hover effects for nodes
            const graphNodes = attackPathGraph.querySelectorAll('.graph-node');
            const graphTooltip = document.createElement('div');
            graphTooltip.className = 'graph-tooltip';
            attackPathGraph.appendChild(graphTooltip);
            
            graphNodes.forEach(node => {
                node.addEventListener('mouseenter', (e) => {
                    const tooltip = e.target.getAttribute('data-tooltip');
                    if (tooltip) {
                        graphTooltip.textContent = tooltip;
                        graphTooltip.style.display = 'block';
                        
                        // Position tooltip near the node
                        const rect = e.target.getBoundingClientRect();
                        const containerRect = attackPathGraph.getBoundingClientRect();
                        graphTooltip.style.left = `${rect.left - containerRect.left + rect.width/2}px`;
                        graphTooltip.style.top = `${rect.top - containerRect.top - 50}px`;
                    }
                });
                
                node.addEventListener('mouseleave', () => {
                    graphTooltip.style.display = 'none';
                });
            });
        }

        // Create connection between two nodes in the graph
        function createGraphConnection(fromNode, toNode) {
            const connection = document.createElement('div');
            connection.className = 'graph-connection';
            
            const fromRect = fromNode.getBoundingClientRect();
            const toRect = toNode.getBoundingClientRect();
            const containerRect = attackPathGraph.getBoundingClientRect();
            
            const fromX = fromRect.left + fromRect.width/2 - containerRect.left;
            const fromY = fromRect.top + fromRect.height/2 - containerRect.top;
            const toX = toRect.left + toRect.width/2 - containerRect.left;
            const toY = toRect.top + toRect.height/2 - containerRect.top;
            
            const length = Math.sqrt(Math.pow(toX - fromX, 2) + Math.pow(toY - fromY, 2));
            const angle = Math.atan2(toY - fromY, toX - fromX) * 180 / Math.PI;
            
            connection.style.width = `${length}px`;
            connection.style.left = `${fromX}px`;
            connection.style.top = `${fromY}px`;
            connection.style.transform = `rotate(${angle}deg)`;
            
            attackPathGraph.appendChild(connection);
        }

        // Show Attack Path
        function showAttackPath(findingId) {
            const finding = mockData.findings.find(f => f.id === findingId);
            if (!finding) return;
            
            attackPathModal.classList.add('active');
            
            // Update modal title
            document.querySelector('.attack-path-modal .modal-title').textContent = `Attack Path: ${finding.title}`;
            
            // Clear previous content
            const attackPath = document.getElementById('attackPath');
            attackPath.innerHTML = '';
            
            // Create nodes based on the attack path steps
            const steps = finding.attack_path.steps;
            const impact = finding.attack_path.impact;
            
            // Create nodes
            const internetNode = document.createElement('div');
            internetNode.className = 'node node-internet';
            internetNode.textContent = 'Internet';
            internetNode.style.top = '50px';
            internetNode.style.left = '50px';
            internetNode.setAttribute('data-tooltip', 'External attacker with network access');
            attackPath.appendChild(internetNode);
            
            // Create service node
            const serviceNode = document.createElement('div');
            serviceNode.className = 'node node-service';
            serviceNode.textContent = 'Target Service';
            serviceNode.style.top = '50px';
            serviceNode.style.right = '50px';
            serviceNode.setAttribute('data-tooltip', 'Vulnerable service exposed to the internet');
            attackPath.appendChild(serviceNode);
            
            // Create vulnerability node
            const vulnNode = document.createElement('div');
            vulnNode.className = 'node node-vuln';
            vulnNode.textContent = finding.id;
            vulnNode.style.top = '150px';
            vulnNode.style.left = '50%';
            vulnNode.style.transform = 'translateX(-50%)';
            vulnNode.setAttribute('data-tooltip', `${finding.title} (${finding.severity})`);
            attackPath.appendChild(vulnNode);
            
            // Create step nodes
            steps.forEach((step, index) => {
                const stepNode = document.createElement('div');
                stepNode.className = 'node';
                stepNode.textContent = `Step ${index + 1}`;
                stepNode.style.backgroundColor = 'var(--info)';
                stepNode.style.top = `${250 + index * 60}px`;
                stepNode.style.left = '50%';
                stepNode.style.transform = 'translateX(-50%)';
                stepNode.setAttribute('data-tooltip', step);
                attackPath.appendChild(stepNode);
            });
            
            // Create impact node
            const impactNode = document.createElement('div');
            impactNode.className = 'node node-db';
            impactNode.textContent = 'Impact';
            impactNode.style.bottom = '50px';
            impactNode.style.left = '50%';
            impactNode.style.transform = 'translateX(-50%)';
            impactNode.setAttribute('data-tooltip', impact);
            attackPath.appendChild(impactNode);
            
            // Draw connections
            drawConnections();
            
            // Add hover effects for nodes
            document.querySelectorAll('.node').forEach(node => {
                node.addEventListener('mouseenter', (e) => {
                    const tooltip = document.getElementById('nodeTooltip');
                    tooltip.textContent = e.target.getAttribute('data-tooltip');
                    tooltip.style.display = 'block';
                    
                    // Position tooltip near the node
                    const rect = e.target.getBoundingClientRect();
                    const containerRect = document.getElementById('attackPath').getBoundingClientRect();
                    tooltip.style.left = `${rect.left - containerRect.left + rect.width/2}px`;
                    tooltip.style.top = `${rect.top - containerRect.top - 40}px`;
                });
                
                node.addEventListener('mouseleave', () => {
                    document.getElementById('nodeTooltip').style.display = 'none';
                });
            });
        }

        // Draw connections between nodes
        function drawConnections() {
            const nodes = document.querySelectorAll('.node');
            const connections = [];
            
            // Create connections between consecutive nodes
            for (let i = 0; i < nodes.length - 1; i++) {
                connections.push({ from: nodes[i], to: nodes[i + 1] });
            }
            
            connections.forEach((conn, index) => {
                const fromRect = conn.from.getBoundingClientRect();
                const toRect = conn.to.getBoundingClientRect();
                const containerRect = document.getElementById('attackPath').getBoundingClientRect();
                
                const fromX = fromRect.left + fromRect.width/2 - containerRect.left;
                const fromY = fromRect.top + fromRect.height/2 - containerRect.top;
                const toX = toRect.left + toRect.width/2 - containerRect.left;
                const toY = toRect.top + toRect.height/2 - containerRect.top;
                
                const length = Math.sqrt(Math.pow(toX - fromX, 2) + Math.pow(toY - fromY, 2));
                const angle = Math.atan2(toY - fromY, toX - fromX) * 180 / Math.PI;
                
                const connection = document.createElement('div');
                connection.className = 'connection';
                connection.id = `conn-${index}`;
                connection.style.width = `${length}px`;
                connection.style.left = `${fromX}px`;
                connection.style.top = `${fromY}px`;
                connection.style.transform = `rotate(${angle}deg)`;
                
                document.getElementById('attackPath').appendChild(connection);
            });
        }

        // Show Evidence
        function showEvidence(findingId) {
            const finding = mockData.findings.find(f => f.id === findingId);
            if (finding) {
                evidenceContent.textContent = finding.raw_output;
                evidenceModal.classList.add('active');
            }
        }

        // Copy Evidence
        copyEvidenceBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(evidenceContent.textContent)
                .then(() => {
                    const originalText = copyEvidenceBtn.innerHTML;
                    copyEvidenceBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                    setTimeout(() => {
                        copyEvidenceBtn.innerHTML = originalText;
                    }, 2000);
                })
                .catch(err => {
                    console.error('Failed to copy: ', err);
                });
        });

        // Close Modals
        closeModalButtons.forEach(button => {
            button.addEventListener('click', () => {
                document.querySelectorAll('.modal').forEach(modal => {
                    modal.classList.remove('active');
                });
            });
        });

        // Close modals when clicking outside
        window.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                e.target.classList.remove('active');
            }
        });

        // Chat Assistant
        sendChatBtn.addEventListener('click', sendChatMessage);
        chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                sendChatMessage();
            }
        });

        function sendChatMessage() {
            const message = chatInput.value.trim();
            if (!message) return;
            
            // Add user message
            addChatMessage(message, 'user');
            chatInput.value = '';
            
            // Generate bot response
            setTimeout(() => {
                const response = generateBotResponse(message);
                addChatMessage(response, 'bot');
            }, 1000);
        }

        function addChatMessage(text, sender) {
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${sender}-message`;
            messageDiv.textContent = text;
            chatMessages.appendChild(messageDiv);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }

        function generateBotResponse(message) {
            const lowerMessage = message.toLowerCase();
            
            // Simple keyword-based response generation
            if (lowerMessage.includes('urgent') || lowerMessage.includes('priority')) {
                return "Haan — F-001 Critical (CVE-2021-73492) ka exploit public hai. Top 3 actions: 1) Disable plugin immediately 2) Apply vendor patch 3) Rotate DB credentials.";
            } else if (lowerMessage.includes('kisko') && lowerMessage.includes('pehle')) {
                return "Pehle F-001 (Critical) ko fix karo — WordPress plugin vulnerability hai. Phir F-002 (High) — SSH weak policy. F-003 (High) SQL injection bhi important hai.";
            } else if (lowerMessage.includes('koi') && lowerMessage.includes('dikkat')) {
                return "Tum ek bar aur scan karwa lo. Filhal toh bas yeh 4 vulnerabilities mili hain. Lekin agar tumhe lagta hai kuch aur dikkat ho sakti hai, toh mujhe batao.";
            } else if (lowerMessage.includes('kuch') && lowerMessage.includes('pareshani')) {
                return "Haan batao bhai, main aapki kya madad kar sakta hoon?";
            } else if (lowerMessage.includes('attack path') || lowerMessage.includes('attacker path')) {
                if (lowerMessage.includes('f-001')) {
                    return "F-001 Attack Path: Internet → Web Service → F-001 Vulnerability → File Upload → Remote Code Execution → Database Access. Ye sabse critical hai kyunki attacker directly system pe control le sakta hai.";
                } else if (lowerMessage.includes('f-002')) {
                    return "F-002 Attack Path: Internet → SSH Service → F-002 Vulnerability → Brute Force Attack → Server Access → Privilege Escalation. Ye bhi critical hai kyunki attacker server pe access le sakta hai.";
                } else if (lowerMessage.includes('f-003')) {
                    return "F-003 Attack Path: Internet → Web Service → F-003 Vulnerability → SQL Injection → Database Access → Data Theft. Ye bhi high priority hai kyunki user data compromise ho sakta hai.";
                } else if (lowerMessage.includes('f-004')) {
                    return "F-004 Attack Path: Internet → Web Service → F-004 Vulnerability → Clickjacking → User Session Hijacking → Data Exposure. Ye medium priority hai lekin fix karna chahiye.";
                } else {
                    return "Konse finding ka attack path dekhna chahte ho? Example: 'Attack path for F-001' ya 'F-002 ka attacker path dikhao'";
                }
            } else if (lowerMessage.includes('mitigation') || lowerMessage.includes('fix')) {
                if (lowerMessage.includes('f-001') || lowerMessage.includes('cve-2021')) {
                    return "F-001 mitigation: 1) WP Payments plugin disable karo 2) Latest version install karo 3) File upload functionality temporarily block karo 4) Server par file type restrictions lagao.";
                } else if (lowerMessage.includes('f-002') || lowerMessage.includes('ssh')) {
                    return "F-002 mitigation: 1) SSH ke liye key-based authentication use karo 2) Fail2ban install karo rate limiting ke liye 3) Strong password policy enforce karo 4) SSH port change karo default 22 se.";
                } else if (lowerMessage.includes('f-003') || lowerMessage.includes('sql')) {
                    return "F-003 mitigation: 1) Input validation implement karo 2) Prepared statements use karo 3) Web Application Firewall (WAF) lagao 4) Regular security testing karo.";
                } else if (lowerMessage.includes('f-004')) {
                    return "F-004 mitigation: 1) X-Content-Type-Options header add karo 2) X-Frame-Options set karo 3) Content-Security-Policy implement karo 4) Strict-Transport-Security enable karo.";
                }
                return "Konse vulnerability ki mitigation steps chahiye? Example: 'Mitigation for F-001'";
            } else if (lowerMessage.includes('hello') || lowerMessage.includes('hi') || lowerMessage.includes('namaste')) {
                return "Namaste! Main aapka security assistant hoon. Aap vulnerabilities ke bare mein kuch bhi puch sakte hain — urgency, priority, mitigation, ya attack paths.";
            } else {
                return "Mujhe samajh nahi aaya. Aap yeh puch sakte hain: 'Is this urgent?', 'Kisko pehle fix karna chahiye?', 'Attack path dikhao for F-001', ya 'Mitigation steps for CVE-2021-93852'.";
            }
        }

        // Export PDF Functionality
        exportPdfBtn.addEventListener('click', exportToPdf);

        function exportToPdf() {
            showToast("Generating PDF report...", "success");
            
            // Use html2canvas to capture the report section
            html2canvas(document.getElementById('reportSection')).then(canvas => {
                const imgData = canvas.toDataURL('image/png');
                const { jsPDF } = window.jspdf;
                const pdf = new jsPDF('p', 'mm', 'a4');
                const imgProps = pdf.getImageProperties(imgData);
                const pdfWidth = pdf.internal.pageSize.getWidth();
                const pdfHeight = (imgProps.height * pdfWidth) / imgProps.width;
                
                pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
                pdf.save('VulnScan_Report_' + new Date().toISOString().slice(0, 10) + '.pdf');
                
                showToast("PDF report downloaded successfully!", "success");
            }).catch(error => {
                console.error('Error generating PDF:', error);
                showToast("Error generating PDF. Please try again.", "error");
            });
        }

        // Rescan Functionality
        rescanBtn.addEventListener('click', rescan);

        function rescan() {
            showToast("Starting rescan...", "success");
            
            // Hide report section
            reportSection.classList.remove('active');
            
            // Reset the target section
            document.getElementById('target-section').scrollIntoView({ behavior: 'smooth' });
            
            // Reset authorization checkbox
            authCheckbox.checked = false;
            checkScanButtonState();
            
            // Show success message
            setTimeout(() => {
                showToast("Ready for new scan. Fill in the target details above.", "success");
            }, 1000);
        }

        // Toast notification function
        function showToast(message, type = "success") {
            toastMessage.textContent = message;
            toast.className = 'toast';
            
            if (type === "error") {
                toast.classList.add('error');
                toast.querySelector('i').className = 'fas fa-exclamation-circle';
            } else {
                toast.querySelector('i').className = 'fas fa-check-circle';
            }
            
            toast.classList.add('show');
            
            // Hide toast after 3 seconds
            setTimeout(() => {
                toast.classList.remove('show');
            }, 3000);
        }

        // Scroll animations
        function checkScroll() {
            const fadeElements = document.querySelectorAll('.fade-in');
            
            fadeElements.forEach(element => {
                const elementTop = element.getBoundingClientRect().top;
                const elementVisible = 150;
                
                if (elementTop < window.innerHeight - elementVisible) {
                    element.classList.add('visible');
                }
            });
        }

        // Initialize
        function init() {
            initScannerAnimation();
            checkScanButtonState();
            
            // Set initial input values
            domainInput.value = 'shopka.example';
            ipInput.value = '192.168.1.100';
            
            // Draw attack path connections when window resizes
            window.addEventListener('resize', drawConnections);
            
            // Check scroll position for animations
            window.addEventListener('scroll', checkScroll);
            checkScroll();
        }

        // Start the application
        init();