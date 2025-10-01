<?php

// Array of test values to try for cookie overwriting
// will update, OBVS
$testCookieValues = [
    "admin123",
    "test_session",
    "privileged_user",
    "bypass_auth",
    "elevated_access"
];

function getSessionCookieNames($url) {
    // Ensure URL has protocol
    if (!preg_match('/^https?:\/\//', $url)) {
        $url = 'https://' . $url;
    }
    
    // Initialize cURL
    $ch = curl_init();
    
    // Set cURL options
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_NOBODY => false,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
    ]);
    
    // Execute request
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    
    // Check for errors
    if ($response === false) {
        throw new Exception("cURL Error: " . $error);
    }
    
    if ($httpCode >= 400) {
        throw new Exception("HTTP Error: " . $httpCode);
    }
    
    // Split headers and body
    $headers = substr($response, 0, $headerSize);
    $body = substr($response, $headerSize);
    
    // Extract Set-Cookie headers
    preg_match_all('/Set-Cookie:\s*([^=]+)=[^;\r\n]*[;\r\n]/i', $headers, $matches);
    
    if (empty($matches[1])) {
        return ['cookies' => [], 'body' => $body];
    }
    
    $cookieNames = array_map('trim', $matches[1]);
    
    // Filter for likely session cookies
    $sessionCookies = [];
    $sessionPatterns = [
        '/^(PHPSESSID|JSESSIONID|ASPSESSIONID|SESSION|SID)$/i',
        '/^[A-Z]*SESS(ION)?ID[A-Z]*$/i',
        '/sess/i',
        '/session/i',
        '/^(connect\.sid|express\.sid)$/i',
        '/^_session/i',
        '/sessionid/i'
    ];
    
    foreach ($cookieNames as $cookieName) {
        // Check if cookie matches session patterns
        foreach ($sessionPatterns as $pattern) {
            if (preg_match($pattern, $cookieName)) {
                $sessionCookies[] = $cookieName;
                break;
            }
        }
    }
    
    // If no obvious session cookies found, return all cookies
    if (empty($sessionCookies)) {
        $sessionCookies = $cookieNames;
    }
    
    return ['cookies' => array_unique($sessionCookies), 'body' => $body];
}

function createCookieOverwriteScript($cookieNames, $testValues, $domain = null) {
    $domainPart = $domain ? "; domain=" . $domain : "";
    $cookieNamesJson = json_encode($cookieNames);
    $testValuesJson = json_encode($testValues);
    
    $script = <<<JAVASCRIPT
JAVASCRIPT;
    
    return $script;
}

function injectJavaScriptIntoPage($url, $cookieNames, $testValues) {
    // Parse URL to get domain
    $parsedUrl = parse_url($url);
    $domain = $parsedUrl['host'] ?? null;
    
    // Get page content and cookies
    $result = getSessionCookieNames($url);
    $body = $result['body'];
    
    // Generate JavaScript to overwrite cookies
    $jsScript = createCookieOverwriteScript($cookieNames, $testValues, $domain);
    
    // Add enhanced status div with styling
    $statusDiv = '
<div id="status" style="
    position: fixed; 
    top: 10px; 
    right: 10px; 
    width: 300px;
    max-height: 80vh;
    overflow-y: auto;
    padding: 15px; 
    background: rgba(0,0,0,0.9); 
    color: white; 
    border-radius: 8px; 
    z-index: 9999;
    font-family: monospace;
    font-size: 12px;
    line-height: 1.4;
">
    <div style="font-weight: bold; margin-bottom: 10px; color: #00ff00;">Cookie Overwrite Test</div>
</div>';
    
    // Add CSS styles
    $cssStyles = '
<style>
    #status .attempt { color: #ffaa00; margin: 2px 0; }
    #status .success { color: #00ff00; margin: 2px 0; }
    #status .error { color: #ff4444; margin: 2px 0; }
    #status .complete { color: #00ffff; margin: 10px 0; font-weight: bold; }
    #status .refresh { color: #88aaff; margin: 2px 0; }
    #status .analysis { color: #ffcc00; margin: 2px 0; }
    #status .vulnerability { color: #ff0000; margin: 5px 0; font-weight: bold; background: rgba(255,0,0,0.2); padding: 5px; border-radius: 3px; }
    #status .vuln-details { color: #ff6666; margin: 2px 0; font-size: 11px; }
    #status .finding { color: #ff8888; margin: 2px 0; font-size: 11px; }
    #status .match { color: #ffaaaa; margin: 1px 0; font-size: 10px; max-width: 280px; word-wrap: break-word; }
    #status .clean { color: #88ff88; margin: 2px 0; }
</style>';
    
    $injectionCode = $statusDiv . $cssStyles . $jsScript;
    
    // Try to inject before </body>, fallback to end of document
    if (stripos($body, '</body>') !== false) {
        $modifiedResponse = str_ireplace('</body>', $injectionCode . '</body>', $body);
    } else {
        $modifiedResponse = $body . $injectionCode;
    }
    
    return $modifiedResponse;
}

// Main execution
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $website = trim($_POST['website'] ?? '');
    $action = $_POST['action'] ?? '';
    
    if ($action === 'extract_and_test' && !empty($website)) {
        try {
            // First, extract session cookies
            $result = getSessionCookieNames($website);
            $sessionCookies = $result['cookies'];
            
            if (empty($sessionCookies)) {
                $error = "No session cookies found on " . htmlspecialchars($website);
            } else {
                // Generate and serve the modified page with cookie overwriting
                $modifiedPage = injectJavaScriptIntoPage($website, $sessionCookies, $testCookieValues);
                
                // Output the modified page directly
                header('Content-Type: text/html; charset=UTF-8');
                echo $modifiedPage;
                exit;
            }
            
        } catch (Exception $e) {
            $error = "Error: " . $e->getMessage();
        }
    } elseif ($action === 'extract_only' && !empty($website)) {
        try {
            $result = getSessionCookieNames($website);
            $sessionCookies = $result['cookies'];
            
            if (empty($sessionCookies)) {
                $message = "No session cookies found on " . htmlspecialchars($website);
            } else {
                $message = "Session cookie(s) found on " . htmlspecialchars($website) . ":";
            }
        } catch (Exception $e) {
            $error = "Error: " . $e->getMessage();
        }
    }
}
?><!DOCTYPE html>
<html lang="en">
<head>
    <script src="/scripts/session-cookie-manipulate.js"></script>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Session Cookie Extractor & Overwriter</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            margin-right: 10px;
            margin-bottom: 10px;
        }
        .extract-btn {
            background-color: #007cba;
        }
        .extract-btn:hover {
            background-color: #005a87;
        }
        .test-btn {
            background-color: #dc3545;
        }
        .test-btn:hover {
            background-color: #c82333;
        }
        .result {
            margin-top: 20px;
            padding: 15px;
            border-radius: 4px;
        }
        .success {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        .error {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        .cookie-list {
            margin-top: 10px;
        }
        .cookie-name {
            background-color: #e9ecef;
            padding: 5px 10px;
            margin: 5px 0;
            border-radius: 3px;
            font-family: monospace;
            font-weight: bold;
        }
        .test-values {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .test-value {
            display: inline-block;
            background-color: #6c757d;
            color: white;
            padding: 3px 8px;
            margin: 2px;
            border-radius: 3px;
            font-family: monospace;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Session Cookie Extractor & Overwriter</h1>
                
        <p>Enter a website URL to identify session cookies and optionally test cookie overwriting with predefined values.</p>
        
        <div class="test-values">
            <strong>Test Values Used:</strong><br>
            <?php foreach ($testCookieValues as $value): ?>
                <span class="test-value"><?php echo htmlspecialchars($value); ?></span>
            <?php endforeach; ?>
        </div>
        
        <form method="post">
            <div class="form-group">
                <label for="website">Website URL:</label>
                <input type="text" id="website" name="website" 
                       placeholder="example.com" 
                       value="<?php echo isset($_POST['website']) ? htmlspecialchars($_POST['website']) : ''; ?>">
            </div>
            
            <button type="submit" name="action" value="extract_only" class="extract-btn">
                Extract Cookies Only
            </button>
            
            <button type="submit" name="action" value="extract_and_test" class="test-btn">
                Extract & Test Cookie Overwriting
            </button>
        </form>
        
        <?php if (isset($error)): ?>
            <div class="result error">
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>
        
        <?php if (isset($message)): ?>
            <div class="result success">
                <?php echo $message; ?>
                <?php if (!empty($sessionCookies)): ?>
                    <div class="cookie-list">
                        <?php foreach ($sessionCookies as $cookie): ?>
                            <div class="cookie-name"><?php echo htmlspecialchars($cookie); ?></div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
        
      </body>
</html>
