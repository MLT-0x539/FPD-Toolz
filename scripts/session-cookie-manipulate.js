(function() {
    var cookieNames = {$cookieNamesJson};
    var testValues = {$testValuesJson};
    var currentIndex = 0;
    var currentCookieIndex = 0;
    var isRefreshing = false;
    
    console.log('Starting cookie overwrite test with cookies:', cookieNames);
    console.log('Test values:', testValues);
    
    function getCookie(name) {
        var value = '; ' + document.cookie;
        var parts = value.split('; ' + name + '=');
        if (parts.length == 2) return parts.pop().split(';').shift();
        return null;
    }
    
    function setCookieValue(cookieName, value) {
        document.cookie = cookieName + '=' + value + '; path=/{$domainPart}; secure; samesite=lax';
        console.log('Set cookie:', cookieName, '=', value);
    }
    
    function checkForFPDAndStackTrace() {
        var pageContent = document.documentElement.innerHTML.toLowerCase();
        var findings = [];
        
        // Full Path Disclosure patterns
        var fpdPatterns = [
            /[a-z]:\\\\[^\\s<>"]*\\\\[^\\s<>"]*\\.php/gi,
            /\\/[^\\s<>"]*\\/[^\\s<>"]*\\/[^\\s<>"]*\\.[a-z]{2,4}/gi,
            /c:\\\\[^\\s<>"]*|d:\\\\[^\\s<>"]*|e:\\\\[^\\s<>"]*|f:\\\\[^\\s<>"]*|g:\\\\[^\\s<>"]*|h:\\\\[^\\s<>"]*|i:\\\\[^\\s<>"]*|j:\\\\[^\\s<>"]*|k:\\\\[^\\s<>"]*|l:\\\\[^\\s<>"]*|m:\\\\[^\\s<>"]*|n:\\\\[^\\s<>"]*|o:\\\\[^\\s<>"]*|p:\\\\[^\\s<>"]*|q:\\\\[^\\s<>"]*|r:\\\\[^\\s<>"]*|s:\\\\[^\\s<>"]*|t:\\\\[^\\s<>"]*|u:\\\\[^\\s<>"]*|v:\\\\[^\\s<>"]*|w:\\\\[^\\s<>"]*|x:\\\\[^\\s<>"]*|y:\\\\[^\\s<>"]*|z:\\\\[^\\s<>"]*]/gi,
            /\\/var\\/www\\/|%2fvar%2fwww%2f|%5cvar%5cwww%5c/gi,
            /\\/home\\/[^\\s<>"]*\\/|%2fhome%2f|%5chome%5c/gi,
            /\\/usr\\/share\\/|%2fusr%2fshare%2f|%5cusr%5cshare%5c/gi
        ];
        
        // Stack trace patterns
        var stackTracePatterns = [
            /stack\\s*trace:/gi,
            /#[0-9]+\\s+[^\\n]*\\([^)]*\\):\\s*[0-9]+/gi,
            /at\\s+[a-z_][a-z0-9_]*\\([^)]*\\):[0-9]+/gi,
            /fatal\\s+error:|parse\\s+error:|warning:|notice:/gi,
            /exception\\s*'[^']*'\\s*with\\s*message/gi,
            /uncaught\\s+exception/gi,
            /in\\s+[^\\s]*\\.(php|asp|jsp|py|rb)\\s+on\\s+line\\s+[0-9]+/gi,
            /\\bfile\\s*:\\s*[^\\n]*\\.(php|asp|jsp|py|rb)/gi,
            /\\bline\\s*:\\s*[0-9]+/gi,
            /error_reporting\\(|display_errors|error_log/gi
        ];
        
        // Check for FPD
        fpdPatterns.forEach(function(pattern, index) {
            var matches = pageContent.match(pattern);
            if (matches && matches.length > 0) {
                findings.push({
                    type: 'FPD',
                    pattern: 'Pattern ' + (index + 1),
                    matches: matches.slice(0, 3)
                });
            }
        });
        
        // Check for stack traces
        stackTracePatterns.forEach(function(pattern, index) {
            var matches = pageContent.match(pattern);
            if (matches && matches.length > 0) {
                findings.push({
                    type: 'Stack Trace',
                    pattern: 'Pattern ' + (index + 1),
                    matches: matches.slice(0, 3)
                });
            }
        });
        
        return findings;
    }
    
    function testNextValue() {
        if (currentCookieIndex >= cookieNames.length) {
            document.getElementById('status').innerHTML += '<div class="complete">All cookies tested with all values</div>';
            return;
        }
        
        var currentCookie = cookieNames[currentCookieIndex];
        var currentValue = testValues[currentIndex];
        
        var statusDiv = document.getElementById('status');
        statusDiv.innerHTML += '<div class="attempt">Testing: ' + currentCookie + ' = ' + currentValue + '</div>';
        
        var originalValue = getCookie(currentCookie);
        console.log('Original value for', currentCookie, ':', originalValue);
        
        setCookieValue(currentCookie, currentValue);
        
        setTimeout(function() {
            var newValue = getCookie(currentCookie);
            if (newValue === currentValue) {
                console.log('Success: Cookie', currentCookie, 'set to', currentValue);
                statusDiv.innerHTML += '<div class="success">Cookie set successfully</div>';
                
                sessionStorage.setItem('currentTest', JSON.stringify({
                    cookie: currentCookie,
                    value: currentValue,
                    cookieIndex: currentCookieIndex,
                    valueIndex: currentIndex
                }));
                
                statusDiv.innerHTML += '<div class="refresh">Refreshing page to check for errors...</div>';
                isRefreshing = true;
                
                setTimeout(function() {
                    window.location.reload();
                }, 1000);
                
            } else {
                console.log('✗ Failed: Cookie', currentCookie, 'could not be set to', currentValue);
                statusDiv.innerHTML += '<div class="error">✗ Failed: ' + currentCookie + ' (protection active)</div>';
                
                currentIndex++;
                if (currentIndex >= testValues.length) {
                    currentIndex = 0;
                    currentCookieIndex++;
                }
                
                setTimeout(testNextValue, 1000);
            }
        }, 200);
    }
    
    function handlePostRefresh() {
        var testInfo = sessionStorage.getItem('currentTest');
        if (testInfo) {
            testInfo = JSON.parse(testInfo);
            sessionStorage.removeItem('currentTest');
            
            var statusDiv = document.getElementById('status');
            statusDiv.innerHTML += '<div class="analysis">Analyzing page for FPD/Stack Traces...</div>';
            
            var findings = checkForFPDAndStackTrace();
            
            if (findings.length > 0) {
                statusDiv.innerHTML += '<div class="vulnerability">POTENTIAL FPD FOUND!</div>';
                statusDiv.innerHTML += '<div class="vuln-details">Cookie: ' + testInfo.cookie + ' = ' + testInfo.value + '</div>';
                
                findings.forEach(function(finding) {
                    statusDiv.innerHTML += '<div class="finding">' + finding.type + ' detected (' + finding.pattern + ')</div>';
                    finding.matches.forEach(function(match) {
                        statusDiv.innerHTML += '<div class="match">' + match.substring(0, 100) + '...</div>';
                    });
                });
                
                console.log('FPD FOUND:', findings);
            } else {
                statusDiv.innerHTML += '<div class="clean">No FPD or stack traces detected</div>';
            }
            
            currentIndex = testInfo.valueIndex + 1;
            currentCookieIndex = testInfo.cookieIndex;
            
            if (currentIndex >= testValues.length) {
                currentIndex = 0;
                currentCookieIndex++;
            }
            
            setTimeout(testNextValue, 2000);
        }
    }
    
    setTimeout(function() {
        if (sessionStorage.getItem('currentTest')) {
            handlePostRefresh();
        } else {
            testNextValue();
        }
    }, 500);
})();
