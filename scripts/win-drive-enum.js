        document.getElementById('enumForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const url = document.getElementById('targetUrl').value;
            const loadingDiv = document.getElementById('loadingDiv');
            const resultsSection = document.getElementById('resultsSection');
            const resultsContent = document.getElementById('resultsContent');
            const submitBtn = document.getElementById('submitBtn');
            const progressBar = document.getElementById('progressBar');
            
            // Show loading state
            loadingDiv.classList.add('active');
            resultsSection.style.display = 'none';
            submitBtn.disabled = true;
            submitBtn.textContent = 'Enumerating...';
            
            // Simulate progress
            let progress = 0;
            const progressInterval = setInterval(() => {
                progress += Math.random() * 10;
                if (progress > 90) progress = 90;
                progressBar.style.width = progress + '%';
            }, 200);
            
            try {
                const formData = new FormData();
                formData.append('action', 'enumerate');
                formData.append('url', url);
                
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                clearInterval(progressInterval);
                progressBar.style.width = '100%';
                
                if (data.error) {
                    throw new Error(data.error);
                }
                
                displayResults(data);
                
            } catch (error) {
                clearInterval(progressInterval);
                resultsContent.innerHTML = `
                    <div class="error">
                        <strong>Error:</strong> ${error.message}
                    </div>
                `;
            } finally {
                loadingDiv.classList.remove('active');
                resultsSection.style.display = 'block';
                submitBtn.disabled = false;
                submitBtn.textContent = 'Enumerate Drive Letters';
                setTimeout(() => {
                    progressBar.style.width = '0%';
                }, 1000);
            }
        });

        function displayResults(data) {
            const resultsContent = document.getElementById('resultsContent');
            
            let resultsHTML = `
                <div class="summary">
                    <h4>Scan Summary</h4>
                    <strong>Target URL:</strong> ${data.target_url}<br>
                    <strong>Scan Time:</strong> ${data.scan_time} seconds<br>
                    <strong>Completed:</strong> ${data.timestamp}<br>
                    <strong>Accessible Drives:</strong> ${data.total_accessible} found
                </div>
            `;
            
            if (data.primary_drive) {
                resultsHTML += `
                    <div class="drive-result" style="background: #d4edda; border-left: 4px solid #28a745;">
                        <div class="drive-letter accessible">${data.primary_drive}:\\ (Primary Drive)</div>
                        <span class="status readable">ACCESSIBLE</span>
                        <br><small><strong>This appears to be the main accessible drive for further testing.</strong></small>
                    </div>
                `;
            }
            
            // Show all tested drives
            data.results.forEach(drive => {
                let statusHtml = '';
                let extraInfo = '';
                
                if (drive.readable) {
                    statusHtml = '<span class="status exists">EXISTS</span><span class="status readable">ACCESSIBLE</span>';
                    extraInfo = `<br><small>Response time: ${drive.response_time}ms | Parameter: ${drive.parameter_used} | Indicator: "${drive.indicator_found}"</small>`;
                } else if (drive.exists) {
                    statusHtml = '<span class="status exists">EXISTS</span>';
                } else {
                    statusHtml = '<span class="status not-found">NOT ACCESSIBLE</span>';
                }
                
                const driveClass = drive.readable ? 'accessible' : '';
                
                resultsHTML += `
                    <div class="drive-result">
                        <div class="drive-letter ${driveClass}">${drive.letter}:\\</div>
                        ${statusHtml}
                        ${extraInfo}
                    </div>
                `;
            });
            
            if (data.accessible_drives.length > 0) {
                resultsHTML += `
                    <div class="summary">
                        <h4>Accessible Drives Found</h4>
                        <strong>Drives:</strong> ${data.accessible_drives.join(', ')}<br>
                        <strong>Recommendation:</strong> Use <code>${data.primary_drive}:\\</code> as the primary drive letter for file inclusion attacks.
                    </div>
                `;
            } else {
                resultsHTML += `
                    <div class="error">
                        <strong>No accessible drives found.</strong> The target may not be vulnerable to file inclusion, or additional techniques may be required.
                    </div>
                `;
            }
            
            resultsContent.innerHTML = resultsHTML;
        }

