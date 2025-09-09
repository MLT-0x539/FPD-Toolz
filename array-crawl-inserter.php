<?php

set_time_limit(600); // 10 minutes max execution time

class AdvancedPHPCrawler {
    private $baseUrl;
    private $domain;
    private $visitedUrls = [];
    private $foundPhpScripts = [];
    private $discoveredPaths = [];
    private $vulnerabilities = [];
    private $maxDepth = 3;
    private $maxUrls = 100;
    private $currentDepth = 0;
    private $urlCount = 0;
    
    public function __construct($url, $maxDepth = 3, $maxUrls = 100) {
        $this->baseUrl = $this->normalizeUrl($url);
        $this->domain = parse_url($this->baseUrl, PHP_URL_HOST);
        $this->maxDepth = $maxDepth;
        $this->maxUrls = $maxUrls;
    }
    
    private function normalizeUrl($url) {
        if (!preg_match('/^https?:\/\//', $url)) {
            $url = 'https://' . $url;
        }
        return rtrim($url, '/');
    }
    
    private function fetchPage($url) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (compatible; PHPCrawler/1.0)',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_HEADER => true,
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);
        
        if ($response === false || $httpCode >= 400) {
            return false;
        }
        
        $headers = substr($response, 0, $headerSize);
        $body = substr($response, $headerSize);
        
        return [
            'headers' => $headers,
            'body' => $body,
            'http_code' => $httpCode
        ];
    }
    
    private function extractParameters($html, $scriptUrl) {
        $parameters = [];
        
        // Extract parameters from forms
        $dom = new DOMDocument();
        @$dom->loadHTML($html);
        
        $forms = $dom->getElementsByTagName('form');
        foreach ($forms as $form) {
            $inputs = $form->getElementsByTagName('input');
            foreach ($inputs as $input) {
                $name = $input->getAttribute('name');
                if ($name && !in_array($name, $parameters)) {
                    $parameters[] = $name;
                }
            }
            
            $selects = $form->getElementsByTagName('select');
            foreach ($selects as $select) {
                $name = $select->getAttribute('name');
                if ($name && !in_array($name, $parameters)) {
                    $parameters[] = $name;
                }
            }
            
            $textareas = $form->getElementsByTagName('textarea');
            foreach ($textareas as $textarea) {
                $name = $textarea->getAttribute('name');
                if ($name && !in_array($name, $parameters)) {
                    $parameters[] = $name;
                }
            }
        }
        
        // Extract parameters from JavaScript and links
        preg_match_all('/[?&]([a-zA-Z_][a-zA-Z0-9_]*)\s*=/', $html, $jsParams);
        foreach ($jsParams[1] as $param) {
            if (!in_array($param, $parameters)) {
                $parameters[] = $param;
            }
        }
        
        // Extract parameters from URL query strings in links
        preg_match_all('/href\s*=\s*["\']([^"\']*\?[^"\']*)["\']/', $html, $linkMatches);
        foreach ($linkMatches[1] as $link) {
            $query = parse_url($link, PHP_URL_QUERY);
            if ($query) {
                parse_str($query, $queryParams);
                foreach (array_keys($queryParams) as $param) {
                    if (!in_array($param, $parameters)) {
                        $parameters[] = $param;
                    }
                }
            }
        }
        
        // Common parameter names to test
        // IMPLEMENT THIRD-PARTY PARAM FUZZER HERE
        $commonParams = [
            'id', 'page', 'file', 'path', 'url', 'action', 'cmd', 'exec',
            'include', 'require', 'load', 'view', 'show', 'display',
            'cat', 'dir', 'list', 'read', 'open', 'get', 'fetch'
        ];
        
        foreach ($commonParams as $param) {
            if (!in_array($param, $parameters)) {
                $parameters[] = $param;
            }
        }
        
        return $parameters;
    }
    
    private function testParameterForFPD($scriptUrl, $parameter) {
        // Create malformed array parameter
        $testUrl = $scriptUrl . (strpos($scriptUrl, '?') !== false ? '&' : '?') . $parameter . '[]=1';
        
        echo "Testing parameter: " . htmlspecialchars($parameter) . " on " . htmlspecialchars($scriptUrl) . "<br>\n";
        flush();
        
        $response = $this->fetchPage($testUrl);
        if (!$response) {
            return null;
        }
        
        // Check for Full Path Disclosure and Stack Traces
        $findings = $this->analyzeFPDAndStackTrace($response['body'], $testUrl, $parameter);
        
        if (!empty($findings)) {
            echo "<span style='color: red;'>FPD FOUND!</span><br>\n";
            flush();
            
            // Extract and store full paths
            foreach ($findings as $finding) {
                if (isset($finding['extracted_paths']) && !empty($finding['extracted_paths'])) {
                    foreach ($finding['extracted_paths'] as $path) {
                        if (!in_array($path, $this->discoveredPaths)) {
                            $this->discoveredPaths[] = $path;
                        }
                    }
                }
            }
            
            $this->vulnerabilities[] = [
                'url' => $scriptUrl,
                'test_url' => $testUrl,
                'parameter' => $parameter,
                'findings' => $findings,
                'timestamp' => date('Y-m-d H:i:s')
            ];
            
            return $findings;
        }
        
        return null;
    }
    
    private function analyzeFPDAndStackTrace($content, $url, $parameter) {
        $findings = [];
        $content_lower = strtolower($content);
        
        // Full Path Disclosure patterns with path extraction
        $fpdPatterns = [
            'windows_paths' => '/([a-z]:\\\\[^\\s<>"\'\r\n]*\\\\[^\\s<>"\'\r\n]*)/i',
            'linux_paths' => '/(\\/(?:var|home|usr|etc|opt|tmp)(?:\\/[^\\s<>"\'\r\n]*)*)/i',
            'generic_paths' => '/(\\/[a-zA-Z0-9_-]+(?:\\/[a-zA-Z0-9_-]+)*\\/[a-zA-Z0-9_.-]+\\.php)/i',
            'web_paths' => '/(\\/(?:var\\/www|home\\/[^\\s\\/]+\\/public_html|usr\\/share\\/nginx)(?:\\/[^\\s<>"\'\r\n]*)*)/i'
        ];
        
        // Stack trace patterns
        $stackTracePatterns = [
            'php_fatal' => '/fatal\\s+error[^\\n\\r]*in\\s+([^\\s]+)\\s+on\\s+line\\s+([0-9]+)/i',
            'php_warning' => '/warning[^\\n\\r]*in\\s+([^\\s]+)\\s+on\\s+line\\s+([0-9]+)/i',
            'php_notice' => '/notice[^\\n\\r]*in\\s+([^\\s]+)\\s+on\\s+line\\s+([0-9]+)/i',
            'php_parse' => '/parse\\s+error[^\\n\\r]*in\\s+([^\\s]+)\\s+on\\s+line\\s+([0-9]+)/i',
            'stack_trace' => '/stack\\s+trace:/i',
            'call_stack' => '/#[0-9]+\\s+([^\\n\\r()]+)\\([^)]*\\)/i'
        ];
        
        // Check for FPD patterns
        foreach ($fpdPatterns as $patternName => $pattern) {
            if (preg_match_all($pattern, $content, $matches, PREG_SET_ORDER)) {
                $extractedPaths = [];
                foreach ($matches as $match) {
                    $path = $match[1];
                    // Clean up the path
                    $path = trim($path, '"\'<>');
                    if (strlen($path) > 5 && !in_array($path, $extractedPaths)) {
                        $extractedPaths[] = $path;
                    }
                }
                
                if (!empty($extractedPaths)) {
                    $findings[] = [
                        'type' => 'Full Path Disclosure',
                        'pattern' => $patternName,
                        'extracted_paths' => $extractedPaths,
                        'sample_matches' => array_slice($extractedPaths, 0, 3)
                    ];
                }
            }
        }
        
        // Check for stack trace patterns
        foreach ($stackTracePatterns as $patternName => $pattern) {
            if (preg_match_all($pattern, $content, $matches, PREG_SET_ORDER)) {
                $extractedInfo = [];
                foreach ($matches as $match) {
                    if (isset($match[1])) {
                        $info = trim($match[1], '"\'<>');
                        if (strlen($info) > 3) {
                            $extractedInfo[] = $info;
                            
                            // Try to extract path from the info
                            if (preg_match('/([a-z]:\\\\[^\\s<>"\'\r\n]*|\\\/[^\\s<>"\'\r\n]+)/', $info, $pathMatch)) {
                                $path = $pathMatch[1];
                                if (!in_array($path, $this->discoveredPaths)) {
                                    $this->discoveredPaths[] = $path;
                                }
                            }
                        }
                    }
                }
                
                if (!empty($extractedInfo)) {
                    $findings[] = [
                        'type' => 'Stack Trace',
                        'pattern' => $patternName,
                        'extracted_paths' => $extractedInfo,
                        'sample_matches' => array_slice($extractedInfo, 0, 3)
                    ];
                }
            }
        }
        
        return $findings;
    }
    
    private function extractLinks($html, $currentUrl) {
        $links = [];
        $dom = new DOMDocument();
        @$dom->loadHTML($html);
        
        // Extract links from <a> tags
        $anchors = $dom->getElementsByTagName('a');
        foreach ($anchors as $anchor) {
            $href = $anchor->getAttribute('href');
            if ($href) {
                $absoluteUrl = $this->resolveUrl($href, $currentUrl);
                if ($absoluteUrl && $this->isValidUrl($absoluteUrl)) {
                    $links[] = $absoluteUrl;
                }
            }
        }
        
        // Extract links from <form> tags
        $forms = $dom->getElementsByTagName('form');
        foreach ($forms as $form) {
            $action = $form->getAttribute('action');
            if ($action) {
                $absoluteUrl = $this->resolveUrl($action, $currentUrl);
                if ($absoluteUrl && $this->isValidUrl($absoluteUrl)) {
                    $links[] = $absoluteUrl;
                }
            }
        }
        
        // Extract JavaScript links
        preg_match_all('/["\']([^"\']*\.php[^"\']*)["\']/', $html, $jsMatches);
        foreach ($jsMatches[1] as $jsUrl) {
            $absoluteUrl = $this->resolveUrl($jsUrl, $currentUrl);
            if ($absoluteUrl && $this->isValidUrl($absoluteUrl)) {
                $links[] = $absoluteUrl;
            }
        }
        
        return array_unique($links);
    }
    
    private function resolveUrl($url, $baseUrl) {
        if (preg_match('/^https?:\/\//', $url)) {
            return $url;
        }
        
        $baseParts = parse_url($baseUrl);
        
        if (substr($url, 0, 2) === '//') {
            return $baseParts['scheme'] . ':' . $url;
        }
        
        if (substr($url, 0, 1) === '/') {
            return $baseParts['scheme'] . '://' . $baseParts['host'] . 
                   (isset($baseParts['port']) ? ':' . $baseParts['port'] : '') . $url;
        }
        
        $basePath = isset($baseParts['path']) ? dirname($baseParts['path']) : '';
        if ($basePath === '.') $basePath = '';
        
        return $baseParts['scheme'] . '://' . $baseParts['host'] . 
               (isset($baseParts['port']) ? ':' . $baseParts['port'] : '') . 
               $basePath . '/' . $url;
    }
    
    private function isValidUrl($url) {
        $parsed = parse_url($url);
        
        if (!isset($parsed['host']) || $parsed['host'] !== $this->domain) {
            return false;
        }
        
        if (isset($parsed['scheme']) && !in_array($parsed['scheme'], ['http', 'https'])) {
            return false;
        }
        
        return true;
    }
    
    private function isPhpScript($url, $response = null) {
        $path = parse_url($url, PHP_URL_PATH);
        if (preg_match('/\.php($|\?|#)/', $path)) {
            return true;
        }
        
        if ($response && isset($response['headers'])) {
            $headers = strtolower($response['headers']);
            if (strpos($headers, 'x-powered-by: php') !== false ||
                strpos($headers, 'server: php') !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    private function crawlUrl($url, $depth = 0) {
        if ($depth > $this->maxDepth || $this->urlCount >= $this->maxUrls) {
            return;
        }
        
        if (in_array($url, $this->visitedUrls)) {
            return;
        }
        
        $this->visitedUrls[] = $url;
        $this->urlCount++;
        
        echo "Crawling: " . htmlspecialchars($url) . " (depth: $depth)<br>\n";
        flush();
        
        $response = $this->fetchPage($url);
        if (!$response) {
            return;
        }
        
        // Check if this is a PHP script
        if ($this->isPhpScript($url, $response)) {
            $scriptInfo = [
                'url' => $url,
                'http_code' => $response['http_code'],
                'discovered_at_depth' => $depth,
                'discovery_method' => $this->getDiscoveryMethod($url),
                'parameters' => [],
                'tested_parameters' => []
            ];
            
            // Extract parameters from the PHP script
            $parameters = $this->extractParameters($response['body'], $url);
            $scriptInfo['parameters'] = $parameters;
            
            echo "<span style='color: blue;'>PHP Script found with " . count($parameters) . " parameters</span><br>\n";
            flush();
            
            // Test each parameter for FPD vulnerabilities
            foreach ($parameters as $parameter) {
                $findings = $this->testParameterForFPD($url, $parameter);
                if ($findings) {
                    $scriptInfo['tested_parameters'][] = [
                        'parameter' => $parameter,
                        'vulnerable' => true,
                        'findings' => $findings
                    ];
                } else {
                    $scriptInfo['tested_parameters'][] = [
                        'parameter' => $parameter,
                        'vulnerable' => false
                    ];
                }
                
                // Small delay to be respectful
                usleep(500000); // 0.5 seconds
            }
            
            $this->foundPhpScripts[] = $scriptInfo;
        }
        
        // Extract and crawl links if within depth limit
        if ($depth < $this->maxDepth) {
            $links = $this->extractLinks($response['body'], $url);
            foreach ($links as $link) {
                if ($this->urlCount < $this->maxUrls) {
                    $this->crawlUrl($link, $depth + 1);
                }
            }
        }
    }
    
    private function getDiscoveryMethod($url) {
        $path = parse_url($url, PHP_URL_PATH);
        if (preg_match('/\.php($|\?|#)/', $path)) {
            return 'URL Extension';
        }
        return 'Response Analysis';
    }
    
    public function crawl() {
        echo "<div class='crawl-status'>Starting advanced crawl of: " . htmlspecialchars($this->baseUrl) . "</div><br>\n";
        flush();
        
        $this->crawlUrl($this->baseUrl);
        
        // Try common PHP file patterns
        $this->tryCommonPaths();
        
        return $this->foundPhpScripts;
    }
    
    private function tryCommonPaths() {
        $commonPaths = [
            '/index.php', '/admin.php', '/login.php', '/config.php',
            '/admin/index.php', '/admin/login.php', '/admin/admin.php',
            '/wp-admin/admin.php', '/wp-login.php', '/wp-admin/index.php',
            '/administrator/index.php', '/phpmyadmin/index.php',
            '/test.php', '/info.php', '/phpinfo.php', '/status.php',
            '/api.php', '/upload.php', '/download.php', '/search.php',
            '/contact.php', '/about.php', '/profile.php', '/settings.php'
        ];
        
        echo "<br><div class='crawl-status'>Testing common PHP paths...</div><br>\n";
        flush();
        
        foreach ($commonPaths as $path) {
            if ($this->urlCount >= $this->maxUrls) break;
            
            $testUrl = $this->baseUrl . $path;
            if (!in_array($testUrl, $this->visitedUrls)) {
                $response = $this->fetchPage($testUrl);
                if ($response && $response['http_code'] === 200) {
                    echo "Found: " . htmlspecialchars($testUrl) . "<br>\n";
                    flush();
                    
                    // Extract parameters and test for FPD
                    $parameters = $this->extractParameters($response['body'], $testUrl);
                    
                    $scriptInfo = [
                        'url' => $testUrl,
                        'http_code' => $response['http_code'],
                        'discovered_at_depth' => 'common_path',
                        'discovery_method' => 'Common Path Testing',
                        'parameters' => $parameters,
                        'tested_parameters' => []
                    ];
                    
                    // Test parameters
                    foreach ($parameters as $parameter) {
                        $findings = $this->testParameterForFPD($testUrl, $parameter);
                        if ($findings) {
                            $scriptInfo['tested_parameters'][] = [
                                'parameter' => $parameter,
                                'vulnerable' => true,
                                'findings' => $findings
                            ];
                        } else {
                            $scriptInfo['tested_parameters'][] = [
                                'parameter' => $parameter,
                                'vulnerable' => false
                            ];
                        }
                        usleep(500000); // 0.5 seconds delay
                    }
                    
                    $this->foundPhpScripts[] = $scriptInfo;
                }
                $this->visitedUrls[] = $testUrl;
                $this->urlCount++;
            }
        }
    }
    
    public function getResults() {
        return [
            'php_scripts' => $this->foundPhpScripts,
            'total_urls_visited' => count($this->visitedUrls),
            'total_php_scripts' => count($this->foundPhpScripts),
            'vulnerabilities' => $this->vulnerabilities,
            'discovered_paths' => $this->discoveredPaths,
            'total_vulnerabilities' => count($this->vulnerabilities)
        ];
    }
}

// Main execution
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['target_url'])) {
    $targetUrl = trim($_POST['target_url']);
    $maxDepth = intval($_POST['max_depth'] ?? 2);
    $maxUrls = intval($_POST['max_urls'] ?? 30);
    
    if (!empty($targetUrl)) {
        echo "<div class='results-container'>";
        
        try {
            $crawler = new AdvancedPHPCrawler($targetUrl, $maxDepth, $maxUrls);
            
            echo "<div class='crawl-output'>";
            $phpScripts = $crawler->crawl();
            echo "</div>";
            
            $results = $crawler->getResults();
            
        } catch (Exception $e) {
            $error = "Error: " . $e->getMessage();
        }
        
        echo "</div>";
    } else {
        $error = "Please enter a valid URL.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced PHP Script Crawler with FPD Testing</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1200px;
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
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], input[type="number"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        input[type="number"] {
            width: 100px;
        }
        button {
            background-color: #dc3545;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #c82333;
        }
        .error {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .results-container {
            margin-top: 20px;
        }
        .crawl-output {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 15px;
            border-radius: 4px;
            max-height: 500px;
            overflow-y: auto;
            font-family: monospace;
            font-size: 12px;
        }
        .crawl-status {
            color: #007bff;
            font-weight: bold;
        }
        .results-summary {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .vulnerability-alert {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .php-scripts-list {
            margin-top: 20px;
        }
        .php-script-item {
            background-color: #e9ecef;
            border: 1px solid #dee2e6;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .script-url {
            color: #007bff;
            font-weight: bold;
            word-break: break-all;
            font-family: monospace;
        }
        .script-details {
            font-size: 12px;
            color: #6c757d;
            margin: 5px 0;
        }
        .parameters-list {
            margin-top: 10px;
        }
        .parameter-item {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 8px;
            margin: 3px 0;
            border-radius: 3px;
            font-family: monospace;
            font-size: 12px;
        }
        .vulnerable-param {
            background-color: #f8d7da;
            border-color: #f5c6cb;
            color: #721c24;
        }
        .safe-param {
            background-color: #d4edda;
            border-color: #c3e6cb;
            color: #155724;
        }
        .form-row {
            display: flex;
            gap: 20px;
            align-items: end;
        }
        .form-row .form-group {
            flex: 1;
        }
        .form-row .form-group:last-child {
            flex: 0 0 auto;
        }
        .paths-discovered {
            background-color: #d1ecf1;
            border: 1px solid #bee5eb;
            color: #0c5460;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .path-item {
            font-family: monospace;
            background-color: #e2e3e5;
            padding: 3px 6px;
            margin: 2px;
            border-radius: 3px;
            display: inline-block;
        }
        .vulnerability-details {
            background-color: #fff;
            border: 1px solid #dee2e6;
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .finding-item {
            margin: 5px 0;
            padding: 5px;
            background-color: #ffe6e6;
            border-radius: 3px;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Advanced PHP Script Crawler with FPD Testing</h1>        
        <form method="post">
            <div class="form-group">
                <label for="target_url">Target Website URL:</label>
                <input type="text" id="target_url" name="target_url" 
                       placeholder="example.com" 
                       value="<?php echo isset($_POST['target_url']) ? htmlspecialchars($_POST['target_url']) : ''; ?>" required>
            </div>
            
            <div class="form-row">
                <div class="form-group">
                    <label for="max_depth">Max Crawl Depth:</label>
                    <input type="number" id="max_depth" name="max_depth" 
                           min="1" max="3" 
                           value="<?php echo isset($_POST['max_depth']) ? intval($_POST['max_depth']) : 2; ?>">
                </div>
                
                <div class="form-group">
                    <label for="max_urls">Max URLs to Check:</label>
                    <input type="number" id="max_urls" name="max_urls" 
                           min="5" max="100" 
                           value="<?php echo isset($_POST['max_urls']) ? intval($_POST['max_urls']) : 30; ?>">
                </div>
                
                <div class="form-group">
                    <button type="submit">Start Advanced Crawl</button>
                </div>
            </div>
        </form>
        
        <?php if (isset($error)): ?>
            <div class="error">
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>
        
        <?php if (isset($results)): ?>
            <div class="results-summary">
                <h3>Crawling Results</h3>
                <p><strong>Total URLs Visited:</strong> <?php echo $results['total_urls_visited']; ?></p>
                <p><strong>PHP Scripts Found:</strong> <?php echo $results['total_php_scripts']; ?></p>
                <p><strong>Discoveries:</strong> <?php echo $results['total_vulnerabilities']; ?></p>
                <p><strong>Full Paths Extracted:</strong> <?php echo count($results['discovered_paths']); ?></p>
            </div>
            
            <?php if (!empty($results['vulnerabilities'])): ?>
                <div class="vulnerability-alert">
                    <h3>FPD Found!</h3>
                    <p><strong><?php echo count($results['vulnerabilities']); ?></strong> Full Path Disclosure vulnerabilities detected.</p>
                </div>
            <?php endif; ?>
            
            <?php if (!empty($results['discovered_paths'])): ?>
                <div class="paths-discovered">
                    <h3>Extracted Full Paths</h3>
                    <p>The following full server paths were discovered through vulnerability testing:</p>
                    <?php foreach ($results['discovered_paths'] as $path): ?>
                        <span class="path-item"><?php echo htmlspecialchars($path); ?></span>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            
            <?php if (!empty($results['vulnerabilities'])): ?>
                <div class="php-scripts-list">
                    <h3>Vulnerable Scripts Details</h3>
                    <?php foreach ($results['vulnerabilities'] as $vuln): ?>
                        <div class="vulnerability-details">
                            <div class="script-url"><?php echo htmlspecialchars($vuln['url']); ?></div>
                            <div class="script-details">
                                Vulnerable Parameter: <strong><?php echo htmlspecialchars($vuln['parameter']); ?></strong> | 
                                Test URL: <a href="<?php echo htmlspecialchars($vuln['test_url']); ?>" target="_blank" style="font-size: 10px;"><?php echo htmlspecialchars($vuln['test_url']); ?></a>
                            </div>
                            <?php foreach ($vuln['findings'] as $finding): ?>
                                <div class="finding-item">
                                    <strong><?php echo htmlspecialchars($finding['type']); ?></strong> (<?php echo htmlspecialchars($finding['pattern']); ?>)<br>
                                    <?php if (isset($finding['sample_matches'])): ?>
                                        <?php foreach ($finding['sample_matches'] as $match): ?>
                                            <code style="display: block; margin: 2px 0; word-break: break-all;"><?php echo htmlspecialchars(substr($match, 0, 150)); ?><?php echo strlen($match) > 150 ? '...' : ''; ?></code>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            
            <?php if (!empty($results['php_scripts'])): ?>
                <div class="php-scripts-list">
                    <h3>All Discovered PHP Scripts</h3>
                    <?php foreach ($results['php_scripts'] as $script): ?>
                        <div class="php-script-item">
                            <div class="script-url"><?php echo htmlspecialchars($script['url']); ?></div>
                            <div class="script-details">
                                HTTP: <?php echo $script['http_code']; ?> | 
                                Depth: <?php echo $script['discovered_at_depth']; ?> | 
                                Method: <?php echo htmlspecialchars($script['discovery_method']); ?> |
                                Parameters Found: <?php echo count($script['parameters']); ?>
                            </div>
                            
                            <?php if (!empty($script['parameters'])): ?>
                                <div class="parameters-list">
                                    <strong>Parameters Tested:</strong>
                                    <?php foreach ($script['tested_parameters'] as $testedParam): ?>
                                        <div class="parameter-item <?php echo $testedParam['vulnerable'] ? 'vulnerable-param' : 'safe-param'; ?>">
                                            <?php echo $testedParam['vulnerable'] ? 'No' : 'Yes'; ?> 
                                            <?php echo htmlspecialchars($testedParam['parameter']); ?>[]
                                            <?php if ($testedParam['vulnerable']): ?>
                                                - <strong>VULNERABLE</strong>
                                            <?php else: ?>
                                                - Safe
                                            <?php endif; ?>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <div class="error">
                    No PHP scripts were discovered on the target website.
                </div>
            <?php endif; ?>
        <?php endif; ?>
        
      </body>
</html>
