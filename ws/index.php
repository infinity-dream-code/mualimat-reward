<?php
error_reporting(E_ALL);
ini_set("display_errors", "0");
ini_set("log_errors", "1");
date_default_timezone_set("Asia/Jakarta");

$libDb = __DIR__ . "/lib/DbClass.php";
$libConn = __DIR__ . "/lib/conn.php";
$libJwt = __DIR__ . "/lib/jwt.php";
$cfgDb = __DIR__ . "/config/DbClass.php";
$cfgConn = __DIR__ . "/config/conn.php";
$cfgJwt = __DIR__ . "/config/jwt.php";

if (file_exists($libDb) && file_exists($libConn) && file_exists($libJwt)) {
    require_once $libDb;
    require_once $libConn;
    require_once $libJwt;
} elseif (file_exists($cfgDb) && file_exists($cfgConn) && file_exists($cfgJwt)) {
    require_once $cfgDb;
    require_once $cfgConn;
    require_once $cfgJwt;
} else {
    http_response_code(500);
    header("Content-Type: application/json; charset=utf-8");
    echo json_encode([
        "status" => 500,
        "message" => "Konfigurasi server belum lengkap",
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

const SECURE_INPUT_MAX_UPLOAD_BYTES = 2097152;

const SECURE_INPUT_DANGEROUS_EXT = [
    'php',
    'phtml',
    'php3',
    'php4',
    'php5',
    'php7',
    'php8',
    'phar',
    'phps',
    'cgi',
    'pl',
    'py',
    'rb',
    'exe',
    'dll',
    'so',
    'sh',
    'bash',
    'bat',
    'cmd',
    'com',
    'js',
    'mjs',
    'html',
    'htm',
    'xhtml',
    'svg',
    'asp',
    'aspx',
    'jsp',
    'htaccess',
    'ini',
    'config',
    'shtml',
    'war',
    'jar',
];

const SECURE_INPUT_ALLOWED_METHODS = ['login', 'loginApproval', 'getTahunAkademik', 'getPrestasiKatalog', 'getPrestasiSaya', 'submitPrestasi', 'approval', 'manageUsers', 'manageKatalog'];

function writeLog(string $event, array $context = []): void
{
    $safe = [];
    foreach ($context as $k => $v) {
        if (in_array((string) $k, ['password', 'token'], true)) {
            continue;
        }
        $safe[$k] = $v;
    }
    $line = "[" . date("Y-m-d H:i:s") . "] " . $event . " " . json_encode($safe, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    @file_put_contents(__DIR__ . "/error.log", $line . PHP_EOL, FILE_APPEND);
}

function secure_sanitize_basename(string $filename): string
{
    $filename = str_replace(["\0", '\\'], ['', '/'], $filename);
    $filename = basename($filename);
    return trim($filename);
}

function secure_filename_has_dangerous_part(string $filename): bool
{
    $filename = strtolower(secure_sanitize_basename($filename));
    if ($filename === '') {
        return true;
    }

    $parts = explode('.', $filename);
    foreach ($parts as $part) {
        if ($part === '' || in_array($part, SECURE_INPUT_DANGEROUS_EXT, true)) {
            return true;
        }
    }

    return false;
}

/**
 * @return array{valid: bool, ext: string, error: string}
 */
function secure_inspect_upload(string $tmpPath, string $originalName, int $size): array
{
    $fail = static function (string $error): array {
        return ['valid' => false, 'ext' => '', 'error' => $error];
    };

    if ($size <= 0) {
        return $fail('File wajib diupload');
    }
    if ($size > SECURE_INPUT_MAX_UPLOAD_BYTES) {
        return $fail('Ukuran file maksimal 2MB');
    }
    if (!is_readable($tmpPath)) {
        return $fail('File upload tidak valid');
    }

    $originalName = secure_sanitize_basename($originalName);
    if ($originalName === '' || secure_filename_has_dangerous_part($originalName)) {
        return $fail('Nama file tidak valid');
    }

    $clientExt = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
    if (!in_array($clientExt, ['png', 'jpg', 'jpeg', 'pdf'], true)) {
        return $fail('Format file harus PNG, JPG, atau PDF');
    }

    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    if ($finfo === false) {
        return $fail('File upload tidak valid');
    }
    $mime = (string) finfo_file($finfo, $tmpPath);
    finfo_close($finfo);

    $ext = '';
    if ($mime === 'image/png') {
        $info = @getimagesize($tmpPath);
        if ($info === false || ($info[2] ?? 0) !== IMAGETYPE_PNG) {
            return $fail('File gambar tidak valid');
        }
        $ext = 'png';
    } elseif ($mime === 'image/jpeg') {
        $info = @getimagesize($tmpPath);
        if ($info === false || ($info[2] ?? 0) !== IMAGETYPE_JPEG) {
            return $fail('File gambar tidak valid');
        }
        $ext = 'jpg';
    } elseif ($mime === 'application/pdf') {
        $handle = fopen($tmpPath, 'rb');
        if ($handle === false) {
            return $fail('File upload tidak valid');
        }
        $header = (string) fread($handle, 5);
        fclose($handle);
        if ($header !== '%PDF-') {
            return $fail('File PDF tidak valid');
        }
        $ext = 'pdf';
    } else {
        return $fail('Tipe file tidak valid');
    }

    if ($clientExt === 'pdf' && $ext !== 'pdf') {
        return $fail('Tipe file tidak valid');
    }
    if (in_array($clientExt, ['png', 'jpg', 'jpeg'], true) && !in_array($ext, ['png', 'jpg'], true)) {
        return $fail('Tipe file tidak valid');
    }

    return ['valid' => true, 'ext' => $ext, 'error' => ''];
}

function secure_validate_method(string $method): ?string
{
    $method = trim($method);
    return in_array($method, SECURE_INPUT_ALLOWED_METHODS, true) ? $method : null;
}

function secure_validate_username(string $username): ?string
{
    $username = trim($username);
    if ($username === '' || strlen($username) > 50) {
        return null;
    }
    if (!preg_match('/^[a-zA-Z0-9._@-]+$/', $username)) {
        return null;
    }
    return $username;
}

function secure_validate_password(string $password): ?string
{
    if ($password === '' || strlen($password) > 128) {
        return null;
    }
    if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $password)) {
        return null;
    }
    return $password;
}

function secure_validate_token_format(string $token): bool
{
    $token = trim($token);
    if ($token === '' || strlen($token) > 4096) {
        return false;
    }

    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return false;
    }

    foreach ($parts as $part) {
        if ($part === '' || !preg_match('/^[A-Za-z0-9_-]+$/', $part)) {
            return false;
        }
    }

    return true;
}

function secure_validate_text_field(string $value, int $maxLength, int $minLength = 1): ?string
{
    $value = trim($value);
    if (strlen($value) < $minLength || strlen($value) > $maxLength) {
        return null;
    }
    if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', $value)) {
        return null;
    }
    if (preg_match('/<[^>]*>/', $value)) {
        return null;
    }
    return $value;
}

function secure_validate_nilai_penghargaan(string $value): ?string
{
    $value = trim(str_replace(',', '.', $value));
    if ($value === '') {
        return '0.00';
    }
    if (!preg_match('/^\d{1,13}(\.\d{1,2})?$/', $value)) {
        return null;
    }

    return number_format((float) $value, 2, '.', '');
}

function secure_validate_tahun_akademik(string $value): ?string
{
    $value = trim($value);
    if (!preg_match('/^\d{4}\/\d{4}$/', $value)) {
        return null;
    }

    [$start, $end] = array_map('intval', explode('/', $value));
    if ($end !== $start + 1) {
        return null;
    }

    return $value;
}

function secure_validate_semester(string $value): ?string
{
    $value = trim($value);
    return ($value === '1' || $value === '2') ? $value : null;
}

function secure_validate_nisn(string $value): ?string
{
    $value = trim($value);
    if ($value === '') {
        return '';
    }
    if (!preg_match('/^\d{10}$/', $value)) {
        return null;
    }

    return $value;
}

function secure_validate_positive_id(string $value): ?int
{
    $value = trim($value);
    if (!preg_match('/^[1-9]\d{0,10}$/', $value)) {
        return null;
    }
    $id = (int) $value;
    return $id > 0 ? $id : null;
}

function secure_validate_gdrive_url(string $value): ?string
{
    $value = trim($value);
    if ($value === '' || strlen($value) > 500) {
        return null;
    }
    if (preg_match('/[\x00-\x1F\x7F]/', $value)) {
        return null;
    }

    $parsed = parse_url($value);
    if (!is_array($parsed)) {
        return null;
    }
    if (strtolower((string) ($parsed['scheme'] ?? '')) !== 'https') {
        return null;
    }

    $host = strtolower((string) ($parsed['host'] ?? ''));
    if (str_starts_with($host, 'www.')) {
        $host = substr($host, 4);
    }
    $allowed = ['drive.google.com', 'docs.google.com', 'drive.usercontent.google.com'];
    if (!in_array($host, $allowed, true)) {
        return null;
    }

    return $value;
}

function secure_validate_nocust(string $nocust): bool
{
    return (bool) preg_match('/^[a-zA-Z0-9._-]{1,50}$/', $nocust);
}

function secure_validate_upload_url(string $url, array $allowedHosts = []): bool
{
    $url = trim($url);
    if ($url === '' || strlen($url) > 2048) {
        return false;
    }

    $parsed = parse_url($url);
    if (!is_array($parsed)) {
        return false;
    }

    $scheme = strtolower((string) ($parsed['scheme'] ?? ''));
    if (!in_array($scheme, ['http', 'https'], true)) {
        return false;
    }

    $host = strtolower((string) ($parsed['host'] ?? ''));
    if ($host === '') {
        return false;
    }

    if ($allowedHosts !== []) {
        $allowed = array_map('strtolower', $allowedHosts);
        if (!in_array($host, $allowed, true)) {
            return false;
        }
    }

    $path = (string) ($parsed['path'] ?? '');
    if (
        str_contains($path, '..')
        || str_contains($path, '%')
        || str_contains($path, '\\')
        || !preg_match('#^/uploads/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+\.(png|jpg|pdf)$#', $path)
    ) {
        return false;
    }

    return true;
}

function secure_build_upload_filename(string $jenis, string $keterangan, string $ext): string
{
    $base = slugify_secure($jenis) . '_' . slugify_secure($keterangan);
    $base = trim($base, '_');
    if ($base === '') {
        $base = 'prestasi';
    }

    $base = substr($base, 0, 80);
    $suffix = time() . '_' . bin2hex(random_bytes(4));

    return $base . '_' . $suffix . '.' . $ext;
}

function slugify_secure(string $value): string
{
    $value = strtolower(trim($value));
    $value = preg_replace('/[^a-z0-9]+/', '_', $value);
    return trim((string) $value, '_');
}

function loadEnv(string $path): void
{
    if (!file_exists($path)) {
        http_response_code(500);
        echo json_encode(["status" => 500, "message" => "Konfigurasi server belum lengkap"], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === "" || str_starts_with($line, "#")) continue;
        if (!str_contains($line, "=")) continue;

        [$name, $value] = explode("=", $line, 2);
        $name = trim($name);
        $value = trim($value);
        $value = trim($value, "\"'");

        putenv("$name=$value");
        $_ENV[$name] = $value;
        $_SERVER[$name] = $value;
    }
}

function getJsonInput(): array
{
    // multipart/form-data (upload) → field ada di $_POST, bukan php://input
    if (!empty($_POST)) {
        return $_POST;
    }

    $raw = file_get_contents("php://input");
    $json = json_decode($raw, true);
    return is_array($json) ? $json : [];
}

function dbConnectPdo(): PDO
{
    $host = (string) ($_ENV["DB_HOST"] ?? "");
    $user = (string) ($_ENV["DB_USERNAME"] ?? "");
    $pass = (string) ($_ENV["DB_PASSWORD"] ?? "");
    $port = (string) ($_ENV["DB_PORT"] ?? "3306");
    $name = (string) ($_ENV["DB_DATABASE"] ?? "");

    if ($host === "" || $user === "" || $name === "") {
        throw new RuntimeException("DB_UNAVAILABLE");
    }

    try {
        $conn = new conn();
        $pdo = $conn->DBConnect([
            "host" => $host,
            "user" => $user,
            "pass" => $pass,
            "port" => $port,
            "name" => $name,
        ]);
    } catch (Throwable) {
        writeLog("DB_CONNECT_FAIL", ["host" => $host, "db" => $name, "port" => $port]);
        throw new RuntimeException("DB_UNAVAILABLE");
    }

    if (!$pdo instanceof PDO) {
        throw new RuntimeException("DB_UNAVAILABLE");
    }

    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    return $pdo;
}

function ensureAutoIncrementInsert(PDO $pdo): void
{
    try {
        $mode = (string) $pdo->query("SELECT @@SESSION.sql_mode")->fetchColumn();
        $mode = trim((string) preg_replace('/\bNO_AUTO_VALUE_ON_ZERO\b,?/', '', $mode), ',');
        if ($mode !== '') {
            $pdo->exec("SET SESSION sql_mode = " . $pdo->quote($mode));
        }
    } catch (Throwable) {
        // Abaikan jika server tidak mengizinkan ubah sql_mode.
    }
}

function ensureCatatanAdminColumn(PDO $pdo): void
{
    static $ready = false;
    if ($ready) {
        return;
    }
    try {
        $pdo->query("SELECT catatan_admin FROM aka_reward LIMIT 0");
        $ready = true;
        return;
    } catch (Throwable) {
        // Kolom belum ada.
    }
    try {
        $pdo->exec("ALTER TABLE aka_reward ADD COLUMN catatan_admin VARCHAR(500) NULL DEFAULT NULL AFTER approvedby");
        $ready = true;
    } catch (Throwable $e) {
        $msg = $e->getMessage();
        if (stripos($msg, "Duplicate column") !== false) {
            $ready = true;
            return;
        }
        writeLog("CATATAN_ADMIN_ALTER_FAIL", ["message" => $msg]);
        fail(500, "Kolom catatan_admin belum ada. Jalankan ws/sql/aka_reward_catatan_admin.sql");
    }
}

function allocateRewardId(PDO $pdo): int
{
    $nextId = (int) $pdo->query("SELECT COALESCE(MAX(id), 0) + 1 FROM aka_reward")->fetchColumn();
    return max(1, $nextId);
}

function fetchLastRewardInsertId(PDO $pdo, string $custId, string $nocust, int $fallbackId = 0): int
{
    $insertId = (int) $pdo->lastInsertId();
    if ($insertId > 0) {
        return $insertId;
    }
    if ($fallbackId > 0) {
        return $fallbackId;
    }

    $stmt = $pdo->prepare("
        SELECT id FROM aka_reward
        WHERE custid = :custid AND nocust = :nocust
        ORDER BY created_at DESC, id DESC
        LIMIT 1
    ");
    $stmt->bindValue(":custid", $custId, PDO::PARAM_STR);
    $stmt->bindValue(":nocust", $nocust, PDO::PARAM_STR);
    $stmt->execute();

    return (int) ($stmt->fetchColumn() ?: 0);
}

function buildPublicFileUrl(string $relativePath): string
{
    $baseUrl = trim((string) ($_ENV["PUBLIC_BASE_URL"] ?? ""));
    if ($baseUrl === "") {
        $isHttps = (!empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off")
            || (($_SERVER["SERVER_PORT"] ?? "") === "443");
        $scheme = $isHttps ? "https" : "http";
        $host = (string) ($_SERVER["HTTP_HOST"] ?? "");
        if ($host !== "") {
            $baseUrl = $scheme . "://" . $host;
        }
    }

    $relativePath = "/" . ltrim($relativePath, "/");
    if ($baseUrl === "") {
        return $relativePath;
    }

    return rtrim($baseUrl, "/") . $relativePath;
}

function fail(int $code, string $message): void
{
    http_response_code($code);
    echo json_encode(["status" => $code, "message" => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

function failSystem(int $code = 500): void
{
    fail($code, "Terjadi kesalahan sistem. Silakan coba lagi.");
}

function verifyPassword(string $password, string $stored): bool
{
    $stored = trim($stored);
    if ($stored === "") {
        return false;
    }

    $info = password_get_info($stored);
    if ($info["algo"] !== null) {
        return password_verify($password, $stored);
    }

    $lower = strtolower($stored);

    if (hash_equals($lower, sha1($password))) {
        return true;
    }
    if (hash_equals($lower, hash("sha256", $password))) {
        return true;
    }
    if (hash_equals($lower, md5($password))) {
        return true;
    }

    return hash_equals($stored, $password);
}

function pickRowValue(array $row, array $keys): string
{
    $map = [];
    foreach ($row as $k => $v) {
        $map[strtolower((string) $k)] = $v;
    }
    foreach ($keys as $key) {
        $lk = strtolower((string) $key);
        if (array_key_exists($lk, $map) && trim((string) $map[$lk]) !== '') {
            return trim((string) $map[$lk]);
        }
    }
    return '';
}

function fetchPrestasiUserByLogin(PDO $pdo, string $username): ?array
{
    $stmt = $pdo->prepare("
        SELECT
            u.idincrement,
            u.username,
            u.password,
            u.nama,
            u.role,
            u.code01,
            ms.DESC01 AS nama_sekolah
        FROM prestasi_dan_pelanggaran_user u
        LEFT JOIN mst_sekolah ms ON ms.CODE01 = u.code01
        WHERE TRIM(u.username) = :username
        LIMIT 1
    ");
    $stmt->bindValue(":username", $username, PDO::PARAM_STR);
    $stmt->execute();
    $user = $stmt->fetch();

    return $user ?: null;
}

function fetchSiswaByLogin(PDO $pdo, string $username): ?array
{
    $stmt = $pdo->prepare("
        SELECT
            u.userlogin,
            u.kunci,
            u.urut,
            c.CUSTID,
            c.NOCUST,
            c.NMCUST,
            c.CODE01,
            c.CODE02,
            c.DESC02,
            c.DESC03
        FROM sm_user u
        LEFT JOIN scctcust c ON c.CUSTID = u.urut
        WHERE TRIM(u.userlogin) = :username
        LIMIT 1
    ");
    $stmt->bindValue(":username", $username, PDO::PARAM_STR);
    $stmt->execute();
    $user = $stmt->fetch();

    return $user ?: null;
}

function doLogin(array $req): array
{
    $username = secure_validate_username((string) ($req["username"] ?? ""));
    $password = secure_validate_password((string) ($req["password"] ?? ""));

    if ($username === null || $password === null) {
        writeLog("LOGIN_INVALID_INPUT", ["username" => (string) ($req["username"] ?? "")]);
        fail(422, "Username atau password tidak valid");
    }

    $pdo = dbConnectPdo();
    writeLog("LOGIN_ATTEMPT", ["username" => $username, "source" => "sm_user"]);

    $user = fetchSiswaByLogin($pdo, $username);
    if (!$user) {
        writeLog("LOGIN_USER_NOT_FOUND", ["username" => $username, "source" => "sm_user"]);
        fail(401, "Username atau password salah");
    }

    $storedPassword = pickRowValue($user, ['kunci']);
    if (!verifyPassword($password, $storedPassword)) {
        writeLog("LOGIN_WRONG_PASSWORD", ["username" => $username, "source" => "sm_user"]);
        fail(401, "Username atau password salah");
    }

    $custid = pickRowValue($user, ['CUSTID']);
    $nocust = pickRowValue($user, ['NOCUST', 'userlogin']);
    $nmcust = pickRowValue($user, ['NMCUST']);
    $unit = pickRowValue($user, ['CODE02']);
    $kelas = pickRowValue($user, ['DESC02']);
    $kelompok = pickRowValue($user, ['DESC03']);
    $code01 = pickRowValue($user, ['CODE01']);

    if ($custid === '' || $nocust === '' || !secure_validate_nocust($nocust)) {
        writeLog("LOGIN_USER_DATA_INCOMPLETE", [
            "username" => $username,
            "custid" => $custid,
            "nocust" => $nocust,
            "urut" => pickRowValue($user, ['urut']),
        ]);
        fail(403, "Data akun tidak lengkap");
    }

    $cust = [
        "custid" => $custid,
        "nocust" => $nocust,
        "nmcust" => $nmcust !== '' ? $nmcust : $username,
        "unit"     => $unit,
        "kelas"    => $kelas,
        "kelompok" => $kelompok,
        "code01"   => $code01,
    ];

    writeLog("LOGIN_SUCCESS", ["username" => $username, "custid" => $cust["custid"], "nocust" => $cust["nocust"], "source" => "sm_user"]);

    $jwt = new JWT();
    $key = (string) ($_ENV["JWT_KEY"] ?? "");
    if ($key === "") {
        throw new RuntimeException("CONFIG_ERROR");
    }

    $payload = [
        "custid" => $cust["custid"],
        "nocust" => $cust["nocust"],
        "nmcust" => $cust["nmcust"],
        "unit"     => $cust["unit"],
        "kelas"    => $cust["kelas"],
        "kelompok" => $cust["kelompok"],
        "code01"   => $cust["code01"],
        "iat"      => time(),
        "exp"      => time() + (60 * 60 * 12),
    ];
    $token = $jwt->encode($payload, $key, "HS256");

    return [
        "token"    => $token,
        "custid"   => $cust["custid"],
        "nocust"   => $cust["nocust"],
        "nmcust"   => $cust["nmcust"],
        "unit"     => $cust["unit"],
        "kelas"    => $cust["kelas"],
        "kelompok" => $cust["kelompok"],
        "code01"   => $cust["code01"],
    ];
}

function doLoginApproval(array $req): array
{
    $username = secure_validate_username((string) ($req["username"] ?? ""));
    $password = secure_validate_password((string) ($req["password"] ?? ""));

    if ($username === null || $password === null) {
        writeLog("LOGIN_APPROVAL_INVALID_INPUT", ["username" => (string) ($req["username"] ?? "")]);
        fail(422, "Username atau password tidak valid");
    }

    $pdo = dbConnectPdo();
    writeLog("LOGIN_APPROVAL_ATTEMPT", ["username" => $username]);

    $user = fetchPrestasiUserByLogin($pdo, $username);
    if (!$user) {
        writeLog("LOGIN_APPROVAL_USER_NOT_FOUND", ["username" => $username]);
        fail(401, "Username atau password salah");
    }

    if (!verifyPassword($password, pickRowValue($user, ['password']))) {
        writeLog("LOGIN_APPROVAL_WRONG_PASSWORD", ["username" => $username]);
        fail(401, "Username atau password salah");
    }

    $role = strtolower(trim((string) ($user["role"] ?? "")));
    if (!isApprovalStaffRole($role)) {
        writeLog("LOGIN_APPROVAL_ROLE_FORBIDDEN", ["username" => $username, "role" => $role]);
        fail(403, "Akun ini tidak memiliki akses approval");
    }

    $auth = [
        "userid" => (string) ($user["idincrement"] ?? ""),
        "username" => trim((string) ($user["username"] ?? "")),
        "nama" => trim((string) ($user["nama"] ?? "")),
        "role" => trim((string) ($user["role"] ?? "")),
        "code01" => trim((string) ($user["code01"] ?? "")),
    ];

    if ($auth["userid"] === "" || $auth["username"] === "") {
        writeLog("LOGIN_APPROVAL_DATA_INCOMPLETE", ["username" => $username, "userid" => $auth["userid"]]);
        fail(500, "Data akun tidak lengkap");
    }

    $jwt = new JWT();
    $key = (string) ($_ENV["JWT_KEY"] ?? "");
    if ($key === "") {
        throw new RuntimeException("CONFIG_ERROR");
    }

    $payload = [
        "userid" => $auth["userid"],
        "username" => $auth["username"],
        "nama" => $auth["nama"],
        "role" => $auth["role"],
        "code01" => $auth["code01"],
        "iat" => time(),
        "exp" => time() + (60 * 60 * 12),
    ];
    $token = $jwt->encode($payload, $key, "HS256");
    writeLog("LOGIN_APPROVAL_SUCCESS", ["username" => $auth["username"], "role" => $auth["role"], "code01" => $auth["code01"]]);

    return [
        "token" => $token,
        "userid" => $auth["userid"],
        "username" => $auth["username"],
        "nama" => $auth["nama"],
        "role" => $auth["role"],
        "code01" => $auth["code01"],
    ];
}

function normalizeRole(string $role): string
{
    return strtolower(trim($role));
}

function isApprovalStaffRole(string $role): bool
{
    $role = normalizeRole($role);
    return $role === 'musrifah' || $role === 'superadmin';
}

function isSuperadminRole(string $role): bool
{
    return normalizeRole($role) === 'superadmin';
}

function assertApprovalRole(array $auth): void
{
    $role = (string) ($auth["role"] ?? "");
    if (!isApprovalStaffRole($role)) {
        fail(403, "Akses approval hanya untuk Musrifah dan superadmin");
    }
}

function assertSuperadminRole(array $auth): void
{
    if (!isSuperadminRole((string) ($auth["role"] ?? ""))) {
        fail(403, "Akses ini hanya untuk superadmin");
    }
}

function hashNewPassword(string $password): string
{
    $hash = password_hash($password, PASSWORD_DEFAULT);
    if (!is_string($hash) || $hash === "") {
        throw new RuntimeException("PASSWORD_HASH_ERROR");
    }
    return $hash;
}

function normalizeStaffRoleInput(string $role): ?string
{
    $role = strtolower(trim($role));
    if ($role === "musrifah") {
        return "Musrifah";
    }
    if ($role === "superadmin") {
        return "superadmin";
    }
    return null;
}

function fetchSekolahMap(PDO $pdo): array
{
    $rows = $pdo->query("SELECT CODE01, DESC01 FROM mst_sekolah ORDER BY DESC01 ASC")->fetchAll();
    $items = [];
    foreach ($rows ?: [] as $row) {
        $code = trim((string) ($row["CODE01"] ?? ""));
        if ($code === "") {
            continue;
        }
        $items[] = [
            "code01" => $code,
            "sekolah" => trim((string) ($row["DESC01"] ?? $code)),
        ];
    }
    return $items;
}

function sekolahCodeExists(PDO $pdo, string $code01): bool
{
    $stmt = $pdo->prepare("SELECT 1 FROM mst_sekolah WHERE CODE01 = :code01 LIMIT 1");
    $stmt->bindValue(":code01", $code01, PDO::PARAM_STR);
    $stmt->execute();
    return (bool) $stmt->fetchColumn();
}

function mapAdminUserRow(array $row): array
{
    return [
        "id" => (int) ($row["idincrement"] ?? 0),
        "username" => trim((string) ($row["username"] ?? "")),
        "nama" => trim((string) ($row["nama"] ?? "")),
        "role" => trim((string) ($row["role"] ?? "")),
        "code01" => trim((string) ($row["code01"] ?? "")),
        "sekolah" => trim((string) ($row["sekolah"] ?? "")),
    ];
}

function doManageUsers(array $req, array $auth): array
{
    assertSuperadminRole($auth);
    $action = strtolower(trim((string) ($req["action"] ?? "list")));
    if (!in_array($action, ["list", "create", "update", "delete"], true)) {
        fail(422, "Aksi kelola admin tidak valid");
    }

    $pdo = dbConnectPdo();
    $actorId = (int) ($auth["userid"] ?? 0);

    if ($action === "list") {
        $stmt = $pdo->query("
            SELECT
                u.idincrement,
                u.username,
                u.nama,
                u.role,
                u.code01,
                ms.DESC01 AS sekolah
            FROM prestasi_dan_pelanggaran_user u
            LEFT JOIN mst_sekolah ms ON ms.CODE01 = u.code01
            WHERE u.role IN ('Musrifah', 'superadmin')
            ORDER BY u.role DESC, u.nama ASC
        ");
        $rows = $stmt ? $stmt->fetchAll() : [];
        $items = [];
        foreach ($rows ?: [] as $row) {
            $items[] = mapAdminUserRow($row);
        }

        return [
            "items" => $items,
            "total" => count($items),
            "sekolah" => fetchSekolahMap($pdo),
        ];
    }

    if ($action === "create") {
        $username = secure_validate_username((string) ($req["username"] ?? ""));
        $password = secure_validate_password((string) ($req["password"] ?? ""));
        $nama = secure_validate_text_field((string) ($req["nama"] ?? ""), 50);
        $role = normalizeStaffRoleInput((string) ($req["role"] ?? ""));
        $code01 = trim((string) ($req["code01"] ?? ""));

        if ($username === null || $password === null || $nama === null || $role === null) {
            fail(422, "Data admin tidak valid");
        }
        if (strlen($password) < 4) {
            fail(422, "Password minimal 4 karakter");
        }
        if ($role === "Musrifah") {
            if ($code01 === "" || strlen($code01) > 20) {
                fail(422, "Sekolah wajib diisi untuk Musrifah");
            }
            if (!sekolahCodeExists($pdo, $code01)) {
                fail(422, "Kode sekolah tidak ditemukan");
            }
        } else {
            $code01 = $code01 !== "" && strlen($code01) <= 20 ? $code01 : "";
        }

        $exists = $pdo->prepare("SELECT 1 FROM prestasi_dan_pelanggaran_user WHERE username = :username LIMIT 1");
        $exists->bindValue(":username", $username, PDO::PARAM_STR);
        $exists->execute();
        if ($exists->fetchColumn()) {
            fail(422, "Username sudah digunakan");
        }

        $insert = $pdo->prepare("
            INSERT INTO prestasi_dan_pelanggaran_user (username, password, nama, role, code01)
            VALUES (:username, :password, :nama, :role, :code01)
        ");
        $insert->bindValue(":username", $username, PDO::PARAM_STR);
        $insert->bindValue(":password", hashNewPassword($password), PDO::PARAM_STR);
        $insert->bindValue(":nama", $nama, PDO::PARAM_STR);
        $insert->bindValue(":role", $role, PDO::PARAM_STR);
        $insert->bindValue(":code01", $code01, PDO::PARAM_STR);
        $insert->execute();

        writeLog("ADMIN_USER_CREATE", ["username" => $username, "role" => $role, "by" => (string) ($auth["username"] ?? "")]);
        return ["message" => "Admin berhasil ditambahkan"];
    }

    $id = (int) ($req["id"] ?? 0);
    if ($id <= 0) {
        fail(422, "ID admin tidak valid");
    }

    $find = $pdo->prepare("
        SELECT idincrement, username, role
        FROM prestasi_dan_pelanggaran_user
        WHERE idincrement = :id
        LIMIT 1
    ");
    $find->bindValue(":id", $id, PDO::PARAM_INT);
    $find->execute();
    $target = $find->fetch();
    if (!$target) {
        fail(404, "Admin tidak ditemukan");
    }

    $targetRole = strtolower(trim((string) ($target["role"] ?? "")));
    if ($targetRole === "siswa") {
        fail(422, "Akun siswa tidak dikelola di menu ini");
    }

    if ($action === "delete") {
        if ($actorId > 0 && $id === $actorId) {
            fail(422, "Tidak dapat menghapus akun sendiri");
        }
        $del = $pdo->prepare("DELETE FROM prestasi_dan_pelanggaran_user WHERE idincrement = :id LIMIT 1");
        $del->bindValue(":id", $id, PDO::PARAM_INT);
        $del->execute();
        writeLog("ADMIN_USER_DELETE", ["id" => $id, "username" => (string) ($target["username"] ?? ""), "by" => (string) ($auth["username"] ?? "")]);
        return ["message" => "Admin berhasil dihapus"];
    }

    $username = secure_validate_username((string) ($req["username"] ?? ""));
    $nama = secure_validate_text_field((string) ($req["nama"] ?? ""), 50);
    $role = normalizeStaffRoleInput((string) ($req["role"] ?? ""));
    $code01 = trim((string) ($req["code01"] ?? ""));
    $passwordRaw = (string) ($req["password"] ?? "");

    if ($username === null || $nama === null || $role === null) {
        fail(422, "Data admin tidak valid");
    }
    if ($role === "Musrifah") {
        if ($code01 === "" || strlen($code01) > 20) {
            fail(422, "Sekolah wajib diisi untuk Musrifah");
        }
        if (!sekolahCodeExists($pdo, $code01)) {
            fail(422, "Kode sekolah tidak ditemukan");
        }
    } else {
        $code01 = $code01 !== "" && strlen($code01) <= 20 ? $code01 : "";
    }

    if ($actorId > 0 && $id === $actorId && $role !== "superadmin") {
        fail(422, "Tidak dapat mengubah role akun sendiri");
    }

    $dup = $pdo->prepare("SELECT 1 FROM prestasi_dan_pelanggaran_user WHERE username = :username AND idincrement <> :id LIMIT 1");
    $dup->bindValue(":username", $username, PDO::PARAM_STR);
    $dup->bindValue(":id", $id, PDO::PARAM_INT);
    $dup->execute();
    if ($dup->fetchColumn()) {
        fail(422, "Username sudah digunakan");
    }

    if ($passwordRaw !== "") {
        $password = secure_validate_password($passwordRaw);
        if ($password === null || strlen($password) < 4) {
            fail(422, "Password minimal 4 karakter");
        }
        $upd = $pdo->prepare("
            UPDATE prestasi_dan_pelanggaran_user
            SET username = :username, nama = :nama, role = :role, code01 = :code01, password = :password
            WHERE idincrement = :id
            LIMIT 1
        ");
        $upd->bindValue(":password", hashNewPassword($password), PDO::PARAM_STR);
    } else {
        $upd = $pdo->prepare("
            UPDATE prestasi_dan_pelanggaran_user
            SET username = :username, nama = :nama, role = :role, code01 = :code01
            WHERE idincrement = :id
            LIMIT 1
        ");
    }
    $upd->bindValue(":username", $username, PDO::PARAM_STR);
    $upd->bindValue(":nama", $nama, PDO::PARAM_STR);
    $upd->bindValue(":role", $role, PDO::PARAM_STR);
    $upd->bindValue(":code01", $code01, PDO::PARAM_STR);
    $upd->bindValue(":id", $id, PDO::PARAM_INT);
    $upd->execute();

    writeLog("ADMIN_USER_UPDATE", ["id" => $id, "username" => $username, "role" => $role, "by" => (string) ($auth["username"] ?? "")]);
    return ["message" => "Admin berhasil diperbarui"];
}

function secure_validate_kategori_kode(string $value): ?string
{
    $value = strtoupper(trim($value));
    if (!preg_match('/^[A-Z0-9]{1,10}$/', $value)) {
        return null;
    }
    return $value;
}

function secure_validate_urut(string $value): ?int
{
    $value = trim($value);
    if ($value === "") {
        return null;
    }
    if (!preg_match('/^\d{1,4}$/', $value)) {
        return null;
    }
    return (int) $value;
}

function nextKatalogUrut(PDO $pdo, string $table, string $parentCol = "", int $parentId = 0): int
{
    $allowed = [
        "aka_prestasi_kategori" => true,
        "aka_prestasi_tingkat" => true,
        "aka_prestasi_poin" => true,
    ];
    if (!isset($allowed[$table])) {
        return 1;
    }
    if ($parentCol !== "" && in_array($parentCol, ["kategori_id", "tingkat_id"], true)) {
        $stmt = $pdo->prepare("SELECT COALESCE(MAX(urut), 0) + 1 FROM {$table} WHERE {$parentCol} = :pid");
        $stmt->bindValue(":pid", $parentId, PDO::PARAM_INT);
        $stmt->execute();
        return (int) $stmt->fetchColumn();
    }
    return (int) $pdo->query("SELECT COALESCE(MAX(urut), 0) + 1 FROM {$table}")->fetchColumn();
}

function parseKategoriCode01(PDO $pdo, array $req): string
{
    $code01 = trim((string) ($req["code01"] ?? ""));
    if ($code01 === "") {
        return "";
    }
    if (strlen($code01) > 20 || !sekolahCodeExists($pdo, $code01)) {
        fail(422, "Unit/sekolah tidak valid");
    }
    return $code01;
}

function kategoriVisibleForUnit(string $rowCode01, string $siswaCode01): bool
{
    if ($siswaCode01 === "") {
        return true;
    }
    $rowCode01 = trim($rowCode01);
    return $rowCode01 === "" || $rowCode01 === $siswaCode01;
}

function fetchSiswaCode01ByCustId(PDO $pdo, string $custId): string
{
    $custId = trim($custId);
    if ($custId === "") {
        return "";
    }
    $stmt = $pdo->prepare("SELECT CODE01 FROM scctcust WHERE CUSTID = :id LIMIT 1");
    $stmt->bindValue(":id", $custId, PDO::PARAM_STR);
    $stmt->execute();
    return trim((string) ($stmt->fetchColumn() ?: ""));
}

function resolveSiswaKatalogCode01(PDO $pdo, array $req): string
{
    $token = "";
    if (isset($req["token"]) && is_string($req["token"])) {
        $token = $req["token"];
    } elseif (isset($_SERVER["HTTP_AUTHORIZATION"]) && preg_match('/Bearer\s+(.*)$/i', (string) $_SERVER["HTTP_AUTHORIZATION"], $matches)) {
        $token = $matches[1];
    }
    if ($token === "" || !secure_validate_token_format($token)) {
        return "";
    }
    try {
        $jwt = new JWT();
        $key = (string) ($_ENV["JWT_KEY"] ?? "");
        if ($key === "") {
            return "";
        }
        $decoded = $jwt->decode($token, $key, ["HS256"]);
        if (is_object($decoded)) {
            $decoded = (array) $decoded;
        }
        $code01 = trim((string) ($decoded["code01"] ?? ""));
        if ($code01 !== "") {
            return $code01;
        }
        return fetchSiswaCode01ByCustId($pdo, (string) ($decoded["custid"] ?? ""));
    } catch (Throwable) {
        return "";
    }
}

function filterKatalogByUnit(array $data, string $code01): array
{
    if ($code01 === "") {
        return $data;
    }
    $kategori = [];
    $katIds = [];
    foreach ($data["kategori"] as $row) {
        if (!kategoriVisibleForUnit((string) ($row["code01"] ?? ""), $code01)) {
            continue;
        }
        $kategori[] = $row;
        $katIds[(int) $row["id"]] = true;
    }
    $tingkat = [];
    $lvlIds = [];
    foreach ($data["tingkat"] as $row) {
        if (!isset($katIds[(int) ($row["kategori_id"] ?? 0)])) {
            continue;
        }
        $tingkat[] = $row;
        $lvlIds[(int) $row["id"]] = true;
    }
    $poin = [];
    foreach ($data["poin"] as $row) {
        if (!isset($lvlIds[(int) ($row["tingkat_id"] ?? 0)])) {
            continue;
        }
        $poin[] = $row;
    }
    $data["kategori"] = $kategori;
    $data["tingkat"] = $tingkat;
    $data["poin"] = $poin;
    return $data;
}

function fetchKatalogPayload(PDO $pdo): array
{
    try {
        $kategori = $pdo->query("SELECT id, kode, nama, urut, code01 FROM aka_prestasi_kategori ORDER BY urut ASC, id ASC")->fetchAll();
    } catch (Throwable) {
        fail(500, "Kolom code01 di aka_prestasi_kategori belum ada. Jalankan ws/sql/aka_prestasi_unit.sql");
    }
    $tingkat = $pdo->query("SELECT id, kategori_id, nama, urut FROM aka_prestasi_tingkat ORDER BY urut ASC, id ASC")->fetchAll();
    $poin = $pdo->query("SELECT id, tingkat_id, nama, nilai, urut FROM aka_prestasi_poin ORDER BY urut ASC, id ASC")->fetchAll();

    $mapInt = static function (array $rows, array $keys): array {
        $out = [];
        foreach ($rows as $row) {
            $item = [];
            foreach ($row as $k => $v) {
                if (in_array((string) $k, $keys, true)) {
                    $item[$k] = is_numeric($v) ? (0 + $v) : $v;
                } else {
                    $item[$k] = $v;
                }
            }
            if (isset($item["code01"])) {
                $item["code01"] = trim((string) $item["code01"]);
            }
            $out[] = $item;
        }
        return $out;
    };

    return [
        "kategori" => $mapInt($kategori ?: [], ["id", "urut"]),
        "tingkat" => $mapInt($tingkat ?: [], ["id", "kategori_id", "urut"]),
        "poin" => $mapInt($poin ?: [], ["id", "tingkat_id", "nilai", "urut"]),
        "sekolah" => fetchSekolahMap($pdo),
    ];
}

function doManageKatalog(array $req, array $auth): array
{
    assertSuperadminRole($auth);
    $action = strtolower(trim((string) ($req["action"] ?? "list")));
    $entity = strtolower(trim((string) ($req["entity"] ?? "")));
    if (!in_array($action, ["list", "create", "update", "delete"], true)) {
        fail(422, "Aksi katalog tidak valid");
    }
    if ($action !== "list" && !in_array($entity, ["kategori", "tingkat", "poin"], true)) {
        fail(422, "Jenis katalog tidak valid");
    }

    try {
        $pdo = dbConnectPdo();
        if ($action === "list") {
            return fetchKatalogPayload($pdo);
        }

        $by = (string) ($auth["username"] ?? "");
        $id = (int) ($req["id"] ?? 0);

        if ($entity === "kategori") {
            if ($action === "delete") {
                if ($id <= 0) {
                    fail(422, "ID kategori tidak valid");
                }
                $used = $pdo->prepare("SELECT 1 FROM aka_reward WHERE prestasi_kategori_id = :id LIMIT 1");
                $used->bindValue(":id", $id, PDO::PARAM_INT);
                $used->execute();
                if ($used->fetchColumn()) {
                    fail(422, "Kategori masih dipakai data prestasi");
                }
                $child = $pdo->prepare("SELECT 1 FROM aka_prestasi_tingkat WHERE kategori_id = :id LIMIT 1");
                $child->bindValue(":id", $id, PDO::PARAM_INT);
                $child->execute();
                if ($child->fetchColumn()) {
                    fail(422, "Hapus tingkat di dalam kategori ini terlebih dahulu");
                }
                $del = $pdo->prepare("DELETE FROM aka_prestasi_kategori WHERE id = :id LIMIT 1");
                $del->bindValue(":id", $id, PDO::PARAM_INT);
                $del->execute();
                if ($del->rowCount() < 1) {
                    fail(404, "Kategori tidak ditemukan");
                }
                writeLog("KATALOG_KATEGORI_DELETE", ["id" => $id, "by" => $by]);
                return ["message" => "Kategori berhasil dihapus"];
            }

            $kode = secure_validate_kategori_kode((string) ($req["kode"] ?? ""));
            $nama = secure_validate_text_field((string) ($req["nama"] ?? ""), 120);
            $urutIn = trim((string) ($req["urut"] ?? ""));
            $urut = $urutIn === "" ? null : secure_validate_urut($urutIn);
            $code01 = parseKategoriCode01($pdo, $req);
            if ($kode === null || $nama === null || ($urutIn !== "" && $urut === null)) {
                fail(422, "Data kategori tidak valid");
            }

            if ($action === "create") {
                if ($urut === null) {
                    $urut = nextKatalogUrut($pdo, "aka_prestasi_kategori");
                }
                $dup = $pdo->prepare("SELECT 1 FROM aka_prestasi_kategori WHERE kode = :kode AND code01 = :code01 LIMIT 1");
                $dup->bindValue(":kode", $kode, PDO::PARAM_STR);
                $dup->bindValue(":code01", $code01, PDO::PARAM_STR);
                $dup->execute();
                if ($dup->fetchColumn()) {
                    fail(422, "Kode kategori sudah dipakai untuk unit ini");
                }
                $ins = $pdo->prepare("INSERT INTO aka_prestasi_kategori (kode, nama, urut, code01) VALUES (:kode, :nama, :urut, :code01)");
                $ins->bindValue(":kode", $kode, PDO::PARAM_STR);
                $ins->bindValue(":nama", $nama, PDO::PARAM_STR);
                $ins->bindValue(":urut", $urut, PDO::PARAM_INT);
                $ins->bindValue(":code01", $code01, PDO::PARAM_STR);
                $ins->execute();
                $newId = (int) $pdo->lastInsertId();
                writeLog("KATALOG_KATEGORI_CREATE", ["kode" => $kode, "code01" => $code01, "by" => $by]);
                return ["message" => "Kategori berhasil ditambahkan", "id" => $newId];
            }

            if ($id <= 0) {
                fail(422, "ID kategori tidak valid");
            }
            $dup = $pdo->prepare("SELECT 1 FROM aka_prestasi_kategori WHERE kode = :kode AND code01 = :code01 AND id <> :id LIMIT 1");
            $dup->bindValue(":kode", $kode, PDO::PARAM_STR);
            $dup->bindValue(":code01", $code01, PDO::PARAM_STR);
            $dup->bindValue(":id", $id, PDO::PARAM_INT);
            $dup->execute();
            if ($dup->fetchColumn()) {
                fail(422, "Kode kategori sudah dipakai untuk unit ini");
            }
            if ($urut === null) {
                $cur = $pdo->prepare("SELECT urut FROM aka_prestasi_kategori WHERE id = :id LIMIT 1");
                $cur->bindValue(":id", $id, PDO::PARAM_INT);
                $cur->execute();
                $urut = (int) ($cur->fetchColumn() ?: 0);
            }
            $upd = $pdo->prepare("UPDATE aka_prestasi_kategori SET kode = :kode, nama = :nama, urut = :urut, code01 = :code01 WHERE id = :id LIMIT 1");
            $upd->bindValue(":kode", $kode, PDO::PARAM_STR);
            $upd->bindValue(":nama", $nama, PDO::PARAM_STR);
            $upd->bindValue(":urut", $urut, PDO::PARAM_INT);
            $upd->bindValue(":code01", $code01, PDO::PARAM_STR);
            $upd->bindValue(":id", $id, PDO::PARAM_INT);
            $upd->execute();
            if ($upd->rowCount() < 1) {
                $exists = $pdo->prepare("SELECT 1 FROM aka_prestasi_kategori WHERE id = :id LIMIT 1");
                $exists->bindValue(":id", $id, PDO::PARAM_INT);
                $exists->execute();
                if (!$exists->fetchColumn()) {
                    fail(404, "Kategori tidak ditemukan");
                }
            }
            writeLog("KATALOG_KATEGORI_UPDATE", ["id" => $id, "kode" => $kode, "code01" => $code01, "by" => $by]);
            return ["message" => "Kategori berhasil diperbarui"];
        }

        if ($entity === "tingkat") {
            if ($action === "delete") {
                if ($id <= 0) {
                    fail(422, "ID tingkat tidak valid");
                }
                $used = $pdo->prepare("SELECT 1 FROM aka_reward WHERE prestasi_tingkat_id = :id LIMIT 1");
                $used->bindValue(":id", $id, PDO::PARAM_INT);
                $used->execute();
                if ($used->fetchColumn()) {
                    fail(422, "Tingkat masih dipakai data prestasi");
                }
                $child = $pdo->prepare("SELECT 1 FROM aka_prestasi_poin WHERE tingkat_id = :id LIMIT 1");
                $child->bindValue(":id", $id, PDO::PARAM_INT);
                $child->execute();
                if ($child->fetchColumn()) {
                    fail(422, "Hapus capaian/poin di dalam tingkat ini terlebih dahulu");
                }
                $del = $pdo->prepare("DELETE FROM aka_prestasi_tingkat WHERE id = :id LIMIT 1");
                $del->bindValue(":id", $id, PDO::PARAM_INT);
                $del->execute();
                if ($del->rowCount() < 1) {
                    fail(404, "Tingkat tidak ditemukan");
                }
                writeLog("KATALOG_TINGKAT_DELETE", ["id" => $id, "by" => $by]);
                return ["message" => "Tingkat berhasil dihapus"];
            }

            $kategoriId = secure_validate_positive_id((string) ($req["kategori_id"] ?? ""));
            $nama = secure_validate_text_field((string) ($req["nama"] ?? ""), 120);
            $urutIn = trim((string) ($req["urut"] ?? ""));
            $urut = $urutIn === "" ? null : secure_validate_urut($urutIn);
            if ($kategoriId === null || $nama === null || ($urutIn !== "" && $urut === null)) {
                fail(422, "Data tingkat tidak valid");
            }
            $parent = $pdo->prepare("SELECT 1 FROM aka_prestasi_kategori WHERE id = :id LIMIT 1");
            $parent->bindValue(":id", $kategoriId, PDO::PARAM_INT);
            $parent->execute();
            if (!$parent->fetchColumn()) {
                fail(422, "Kategori tidak ditemukan");
            }

            if ($action === "create") {
                if ($urut === null) {
                    $urut = nextKatalogUrut($pdo, "aka_prestasi_tingkat", "kategori_id", $kategoriId);
                }
                $ins = $pdo->prepare("INSERT INTO aka_prestasi_tingkat (kategori_id, nama, urut) VALUES (:kid, :nama, :urut)");
                $ins->bindValue(":kid", $kategoriId, PDO::PARAM_INT);
                $ins->bindValue(":nama", $nama, PDO::PARAM_STR);
                $ins->bindValue(":urut", $urut, PDO::PARAM_INT);
                $ins->execute();
                $newId = (int) $pdo->lastInsertId();
                writeLog("KATALOG_TINGKAT_CREATE", ["kategori_id" => $kategoriId, "by" => $by]);
                return ["message" => "Tingkat berhasil ditambahkan", "id" => $newId];
            }

            if ($id <= 0) {
                fail(422, "ID tingkat tidak valid");
            }
            if ($urut === null) {
                $cur = $pdo->prepare("SELECT urut FROM aka_prestasi_tingkat WHERE id = :id LIMIT 1");
                $cur->bindValue(":id", $id, PDO::PARAM_INT);
                $cur->execute();
                $urut = (int) ($cur->fetchColumn() ?: 0);
            }
            $upd = $pdo->prepare("UPDATE aka_prestasi_tingkat SET kategori_id = :kid, nama = :nama, urut = :urut WHERE id = :id LIMIT 1");
            $upd->bindValue(":kid", $kategoriId, PDO::PARAM_INT);
            $upd->bindValue(":nama", $nama, PDO::PARAM_STR);
            $upd->bindValue(":urut", $urut, PDO::PARAM_INT);
            $upd->bindValue(":id", $id, PDO::PARAM_INT);
            $upd->execute();
            if ($upd->rowCount() < 1) {
                $exists = $pdo->prepare("SELECT 1 FROM aka_prestasi_tingkat WHERE id = :id LIMIT 1");
                $exists->bindValue(":id", $id, PDO::PARAM_INT);
                $exists->execute();
                if (!$exists->fetchColumn()) {
                    fail(404, "Tingkat tidak ditemukan");
                }
            }
            writeLog("KATALOG_TINGKAT_UPDATE", ["id" => $id, "by" => $by]);
            return ["message" => "Tingkat berhasil diperbarui"];
        }

        if ($action === "delete") {
            if ($id <= 0) {
                fail(422, "ID capaian tidak valid");
            }
            $used = $pdo->prepare("SELECT 1 FROM aka_reward WHERE prestasi_poin_id = :id LIMIT 1");
            $used->bindValue(":id", $id, PDO::PARAM_INT);
            $used->execute();
            if ($used->fetchColumn()) {
                fail(422, "Capaian/poin masih dipakai data prestasi");
            }
            $del = $pdo->prepare("DELETE FROM aka_prestasi_poin WHERE id = :id LIMIT 1");
            $del->bindValue(":id", $id, PDO::PARAM_INT);
            $del->execute();
            if ($del->rowCount() < 1) {
                fail(404, "Capaian tidak ditemukan");
            }
            writeLog("KATALOG_POIN_DELETE", ["id" => $id, "by" => $by]);
            return ["message" => "Capaian berhasil dihapus"];
        }

        $tingkatId = secure_validate_positive_id((string) ($req["tingkat_id"] ?? ""));
        $nama = secure_validate_text_field((string) ($req["nama"] ?? ""), 120);
        $nilai = secure_validate_nilai_penghargaan((string) ($req["nilai"] ?? "0"));
        $urutIn = trim((string) ($req["urut"] ?? ""));
        $urut = $urutIn === "" ? null : secure_validate_urut($urutIn);
        if ($tingkatId === null || $nama === null || $nilai === null || ($urutIn !== "" && $urut === null)) {
            fail(422, "Data capaian tidak valid");
        }
        $parent = $pdo->prepare("SELECT 1 FROM aka_prestasi_tingkat WHERE id = :id LIMIT 1");
        $parent->bindValue(":id", $tingkatId, PDO::PARAM_INT);
        $parent->execute();
        if (!$parent->fetchColumn()) {
            fail(422, "Tingkat tidak ditemukan");
        }

        if ($action === "create") {
            if ($urut === null) {
                $urut = nextKatalogUrut($pdo, "aka_prestasi_poin", "tingkat_id", $tingkatId);
            }
            $ins = $pdo->prepare("INSERT INTO aka_prestasi_poin (tingkat_id, nama, nilai, urut) VALUES (:tid, :nama, :nilai, :urut)");
            $ins->bindValue(":tid", $tingkatId, PDO::PARAM_INT);
            $ins->bindValue(":nama", $nama, PDO::PARAM_STR);
            $ins->bindValue(":nilai", $nilai, PDO::PARAM_STR);
            $ins->bindValue(":urut", $urut, PDO::PARAM_INT);
            $ins->execute();
            $newId = (int) $pdo->lastInsertId();
            writeLog("KATALOG_POIN_CREATE", ["tingkat_id" => $tingkatId, "nilai" => $nilai, "by" => $by]);
            return ["message" => "Capaian berhasil ditambahkan", "id" => $newId];
        }

        if ($id <= 0) {
            fail(422, "ID capaian tidak valid");
        }
        if ($urut === null) {
            $cur = $pdo->prepare("SELECT urut FROM aka_prestasi_poin WHERE id = :id LIMIT 1");
            $cur->bindValue(":id", $id, PDO::PARAM_INT);
            $cur->execute();
            $urut = (int) ($cur->fetchColumn() ?: 0);
        }
        $upd = $pdo->prepare("UPDATE aka_prestasi_poin SET tingkat_id = :tid, nama = :nama, nilai = :nilai, urut = :urut WHERE id = :id LIMIT 1");
        $upd->bindValue(":tid", $tingkatId, PDO::PARAM_INT);
        $upd->bindValue(":nama", $nama, PDO::PARAM_STR);
        $upd->bindValue(":nilai", $nilai, PDO::PARAM_STR);
        $upd->bindValue(":urut", $urut, PDO::PARAM_INT);
        $upd->bindValue(":id", $id, PDO::PARAM_INT);
        $upd->execute();
        if ($upd->rowCount() < 1) {
            $exists = $pdo->prepare("SELECT 1 FROM aka_prestasi_poin WHERE id = :id LIMIT 1");
            $exists->bindValue(":id", $id, PDO::PARAM_INT);
            $exists->execute();
            if (!$exists->fetchColumn()) {
                fail(404, "Capaian tidak ditemukan");
            }
        }
        writeLog("KATALOG_POIN_UPDATE", ["id" => $id, "nilai" => $nilai, "by" => $by]);
        return ["message" => "Capaian berhasil diperbarui"];
    } catch (Throwable $e) {
        writeLog("KATALOG_EXCEPTION", ["message" => $e->getMessage()]);
        fail(500, "Katalog prestasi belum siap. Periksa tabel master di database.");
    }
}

function normalizeRewardApprovalStatus(mixed $raw): string
{
    $value = strtolower(trim((string) $raw));
    if (in_array($value, ['1', 'approve', 'approved'], true)) {
        return 'approve';
    }
    if (in_array($value, ['canceled', 'cancelled', 'reject', 'rejected', 'tolak'], true)) {
        return 'canceled';
    }
    return 'pending';
}

function parseApprovalStatusFilter(string $raw): string
{
    $value = strtolower(trim($raw));
    if ($value === '') {
        return '';
    }
    if (in_array($value, ['0', 'pending'], true)) {
        return 'pending';
    }
    if (in_array($value, ['1', 'approve', 'approved'], true)) {
        return 'approve';
    }
    if (in_array($value, ['canceled', 'cancelled'], true)) {
        return 'canceled';
    }
    return '';
}

function approvalStaffUsername(array $auth): string
{
    $username = trim((string) ($auth["username"] ?? ""));
    if ($username === '') {
        fail(500, "Username petugas tidak ada di sesi");
    }
    return mb_substr($username, 0, 50);
}

function doApproval(array $req, array $auth): array
{
    assertApprovalRole($auth);
    $action = strtolower(trim((string) ($req["action"] ?? "list")));
    if (!in_array($action, ['list', 'approve', 'tolak'], true)) {
        fail(422, "Aksi approval tidak valid");
    }

    $pdo = dbConnectPdo();
    ensureCatatanAdminColumn($pdo);
    $userCode01 = isSuperadminRole((string) ($auth["role"] ?? ""))
        ? ""
        : trim((string) ($auth["code01"] ?? ""));

    if ($action === 'list') {
        $status = parseApprovalStatusFilter((string) ($req["isapproved"] ?? ''));
        $q = trim((string) ($req["q"] ?? ""));
        $tanggalDari = trim((string) ($req["tanggal_dari"] ?? ""));
        $tanggalSampai = trim((string) ($req["tanggal_sampai"] ?? ""));
        $tanggalLegacy = trim((string) ($req["tanggal"] ?? ""));
        if ($tanggalDari !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $tanggalDari)) {
            $tanggalDari = '';
        }
        if ($tanggalSampai !== '' && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $tanggalSampai)) {
            $tanggalSampai = '';
        }
        if ($tanggalLegacy !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $tanggalLegacy)) {
            if ($tanggalDari === '') {
                $tanggalDari = $tanggalLegacy;
            }
            if ($tanggalSampai === '') {
                $tanggalSampai = $tanggalLegacy;
            }
        }

        $sql = "
            SELECT
                ar.id,
                ar.custid,
                ar.nocust,
                ar.nmcust,
                ar.kelas,
                ar.nisn,
                ar.jenis_prestasi,
                ar.prestasi_kategori_id,
                ar.prestasi_tingkat_id,
                ar.prestasi_poin_id,
                apk.kode AS kategori_kode,
                apk.nama AS kategori_nama,
                apt.nama AS tingkat_nama,
                appn.nama AS poin_nama,
                ar.keterangan,
                ar.penyelenggara,
                ar.no_sertifikat,
                ar.nilai_penghargaan,
                ar.bta,
                ar.semester,
                ar.url,
                ar.isapproved,
                ar.approveddate,
                ar.approvedby,
                ar.catatan_admin,
                ar.created_at,
                ar.updated_at,
                sc.CODE01 AS code01,
                ms.DESC01 AS sekolah
            FROM aka_reward ar
            LEFT JOIN scctcust sc ON sc.CUSTID = ar.custid
            LEFT JOIN mst_sekolah ms ON ms.CODE01 = sc.CODE01
            LEFT JOIN aka_prestasi_kategori apk ON apk.id = ar.prestasi_kategori_id
            LEFT JOIN aka_prestasi_tingkat apt ON apt.id = ar.prestasi_tingkat_id
            LEFT JOIN aka_prestasi_poin appn ON appn.id = ar.prestasi_poin_id
            WHERE (:code01_empty = '' OR sc.CODE01 = :code01_value)
        ";
        if ($status === 'pending' || $status === 'approve' || $status === 'canceled') {
            $sql .= " AND ar.isapproved = :isapproved ";
        }
        if ($q !== '') {
            $sql .= " AND (ar.nocust LIKE :q_nocust OR ar.nmcust LIKE :q_nmcust) ";
        }
        if ($tanggalDari !== '') {
            $sql .= " AND DATE(ar.created_at) >= :tanggal_dari ";
        }
        if ($tanggalSampai !== '') {
            $sql .= " AND DATE(ar.created_at) <= :tanggal_sampai ";
        }
        $sql .= " ORDER BY ar.created_at DESC, ar.id DESC LIMIT 1000 ";

        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(":code01_empty", $userCode01, PDO::PARAM_STR);
        $stmt->bindValue(":code01_value", $userCode01, PDO::PARAM_STR);
        if ($status === 'pending' || $status === 'approve' || $status === 'canceled') {
            $stmt->bindValue(":isapproved", $status, PDO::PARAM_STR);
        }
        if ($q !== '') {
            $like = '%' . $q . '%';
            $stmt->bindValue(":q_nocust", $like, PDO::PARAM_STR);
            $stmt->bindValue(":q_nmcust", $like, PDO::PARAM_STR);
        }
        if ($tanggalDari !== '') {
            $stmt->bindValue(":tanggal_dari", $tanggalDari, PDO::PARAM_STR);
        }
        if ($tanggalSampai !== '') {
            $stmt->bindValue(":tanggal_sampai", $tanggalSampai, PDO::PARAM_STR);
        }
        $stmt->execute();
        $rows = $stmt->fetchAll() ?: [];
        foreach ($rows as &$row) {
            if (is_array($row)) {
                $row["isapproved"] = normalizeRewardApprovalStatus($row["isapproved"] ?? "pending");
            }
        }
        unset($row);

        $scopeSekolah = '';
        if ($userCode01 !== '') {
            $schStmt = $pdo->prepare("SELECT DESC01 FROM mst_sekolah WHERE CODE01 = :code01 LIMIT 1");
            $schStmt->bindValue(":code01", $userCode01, PDO::PARAM_STR);
            $schStmt->execute();
            $scopeSekolah = trim((string) ($schStmt->fetchColumn() ?: ''));
        }

        return [
            "items" => $rows,
            "total" => count($rows),
            "scope_code01" => $userCode01,
            "scope_sekolah" => $scopeSekolah,
            "filters" => [
                "q" => $q,
                "tanggal_dari" => $tanggalDari,
                "tanggal_sampai" => $tanggalSampai,
                "isapproved" => $status,
            ],
        ];
    }

    $id = (int) ($req["id"] ?? 0);
    if ($id <= 0) {
        fail(422, "ID approval tidak valid");
    }

    $checkSql = "
        SELECT ar.id
        FROM aka_reward ar
        LEFT JOIN scctcust sc ON sc.CUSTID = ar.custid
        WHERE ar.id = :id
          AND (:code01_empty = '' OR sc.CODE01 = :code01_value)
        LIMIT 1
    ";
    $checkStmt = $pdo->prepare($checkSql);
    $checkStmt->bindValue(":id", $id, PDO::PARAM_INT);
    $checkStmt->bindValue(":code01_empty", $userCode01, PDO::PARAM_STR);
    $checkStmt->bindValue(":code01_value", $userCode01, PDO::PARAM_STR);
    $checkStmt->execute();
    if (!$checkStmt->fetch()) {
        fail(404, "Data tidak ditemukan atau di luar akses sekolah");
    }

    $approvedBy = approvalStaffUsername($auth);
    $nextStatus = $action === 'approve' ? 'approve' : 'canceled';
    $catatanAdmin = null;
    if ($action === 'tolak') {
        $catatanAdmin = secure_validate_text_field((string) ($req["catatan_admin"] ?? ""), 500, 3);
        if ($catatanAdmin === null) {
            fail(422, "Catatan admin wajib diisi saat menolak (3–500 karakter, tanpa HTML)");
        }
    }

    $updateSql = "
        UPDATE aka_reward
        SET isapproved = :isapproved,
            approveddate = NOW(),
            approvedby = :approvedby,
            catatan_admin = :catatan_admin,
            updated_at = NOW()
        WHERE id = :id
        LIMIT 1
    ";
    $updateStmt = $pdo->prepare($updateSql);
    $updateStmt->bindValue(":isapproved", $nextStatus, PDO::PARAM_STR);
    $updateStmt->bindValue(":approvedby", $approvedBy, PDO::PARAM_STR);
    $updateStmt->bindValue(":catatan_admin", $catatanAdmin, $catatanAdmin === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
    $updateStmt->bindValue(":id", $id, PDO::PARAM_INT);
    try {
        $updateStmt->execute();
    } catch (PDOException $e) {
        writeLog("APPROVAL_SQL_FAIL", ["sqlstate" => $e->getCode(), "message" => $e->getMessage()]);
        fail(500, "Kolom isapproved belum ENUM pending/approve/canceled. Jalankan ws/sql/aka_reward_approval_status.sql");
    }

    writeLog("APPROVAL_UPDATE", [
        "id" => $id,
        "action" => $action,
        "status" => $nextStatus,
        "by" => $approvedBy,
        "code01" => $userCode01,
    ]);

    return [
        "id" => $id,
        "isapproved" => $nextStatus,
        "approvedby" => $approvedBy,
        "catatan_admin" => $catatanAdmin,
        "message" => $action === 'approve' ? "Data berhasil disetujui" : "Data berhasil ditolak",
    ];
}

function saveUploadedFile(string $nocust, string $jenisPrestasi, string $keterangan): string
{
    if (!isset($_FILES["file"]) || $_FILES["file"]["error"] !== UPLOAD_ERR_OK) {
        fail(422, "File wajib diupload");
    }

    $file = $_FILES["file"];
    $inspected = secure_inspect_upload(
        (string) $file["tmp_name"],
        (string) ($file["name"] ?? ""),
        (int) ($file["size"] ?? 0)
    );
    if (!$inspected["valid"]) {
        fail(422, $inspected["error"] !== "" ? $inspected["error"] : "File upload tidak valid");
    }

    if (!secure_validate_nocust($nocust)) {
        fail(422, "Data upload tidak valid");
    }

    $uploadRoot = trim((string) ($_ENV["UPLOAD_ABS_PATH"] ?? ""));
    if ($uploadRoot === "") {
        $uploadRoot = __DIR__ . "/public/uploads";
    }
    $uploadRoot = rtrim($uploadRoot, "/\\");

    $folder = $uploadRoot . "/" . $nocust;
    if (!is_dir($folder)) {
        if (!mkdir($folder, 0755, true) && !is_dir($folder)) {
            throw new RuntimeException("UPLOAD_DIR_ERROR");
        }
    }
    if (!is_writable($folder)) {
        throw new RuntimeException("UPLOAD_DIR_ERROR");
    }

    $fileName = secure_build_upload_filename($jenisPrestasi, $keterangan, $inspected["ext"]);
    $target = $folder . "/" . $fileName;

    if (!move_uploaded_file($file["tmp_name"], $target)) {
        throw new RuntimeException("UPLOAD_SAVE_ERROR");
    }

    $urlPrefix = trim((string) ($_ENV["UPLOAD_URL_PREFIX"] ?? "/uploads"));
    $relativePath = rtrim($urlPrefix, "/") . "/" . $nocust . "/" . $fileName;
    return buildPublicFileUrl($relativePath);
}

function validatePrestasiInput(array $req): array
{
    $kategoriId = secure_validate_positive_id((string) ($req["prestasi_kategori_id"] ?? ""));
    $tingkatId = secure_validate_positive_id((string) ($req["prestasi_tingkat_id"] ?? ""));
    $poinId = secure_validate_positive_id((string) ($req["prestasi_poin_id"] ?? ""));
    $keterangan = secure_validate_text_field((string) ($req["keterangan"] ?? ""), 500);
    $penyelenggara = secure_validate_text_field((string) ($req["penyelenggara"] ?? ""), 150);
    $noSertifikat = secure_validate_text_field((string) ($req["no_sertifikat"] ?? ""), 80);
    $tahun = secure_validate_tahun_akademik((string) ($req["tahun_akademik"] ?? ($req["bta"] ?? "")));
    $semester = secure_validate_semester((string) ($req["semester"] ?? ""));
    $nisn = secure_validate_nisn((string) ($req["nisn"] ?? ""));
    $url = secure_validate_gdrive_url((string) ($req["url"] ?? ($req["link_media"] ?? "")));

    if ($kategoriId === null || $tingkatId === null || $poinId === null) {
        fail(422, "Jenis prestasi belum lengkap");
    }
    if ($keterangan === null) {
        fail(422, "Keterangan/deskripsi tidak valid");
    }
    if ($penyelenggara === null) {
        fail(422, "Penyelenggara tidak valid");
    }
    if ($noSertifikat === null) {
        fail(422, "No sertifikat tidak valid");
    }
    if ($tahun === null) {
        fail(422, "Tahun akademik tidak valid");
    }
    if ($semester === null) {
        fail(422, "Semester harus 1 atau 2");
    }
    if ($nisn === null) {
        fail(422, "NISN harus 10 digit angka, atau biarkan kosong");
    }
    if ($url === null) {
        fail(422, "Link harus tautan Google Drive (https://drive.google.com/...)");
    }

    return [
        "prestasi_kategori_id" => $kategoriId,
        "prestasi_tingkat_id" => $tingkatId,
        "prestasi_poin_id" => $poinId,
        "keterangan" => $keterangan,
        "penyelenggara" => $penyelenggara,
        "no_sertifikat" => $noSertifikat,
        "tahun_akademik" => $tahun,
        "semester" => (int) $semester,
        "nisn" => $nisn,
        "url" => $url,
    ];
}

function fetchPrestasiSelection(PDO $pdo, int $kategoriId, int $tingkatId, int $poinId, string $code01 = ""): array
{
    $stmt = $pdo->prepare("
        SELECT
            k.id AS kategori_id,
            k.nama AS kategori_nama,
            k.code01 AS kategori_code01,
            t.id AS tingkat_id,
            t.nama AS tingkat_nama,
            p.id AS poin_id,
            p.nama AS poin_nama,
            p.nilai AS nilai
        FROM aka_prestasi_poin p
        INNER JOIN aka_prestasi_tingkat t ON t.id = p.tingkat_id
        INNER JOIN aka_prestasi_kategori k ON k.id = t.kategori_id
        WHERE p.id = :poin AND t.id = :tingkat AND k.id = :kategori
        LIMIT 1
    ");
    $stmt->bindValue(":poin", $poinId, PDO::PARAM_INT);
    $stmt->bindValue(":tingkat", $tingkatId, PDO::PARAM_INT);
    $stmt->bindValue(":kategori", $kategoriId, PDO::PARAM_INT);
    $stmt->execute();
    $row = $stmt->fetch();
    if (!$row) {
        fail(422, "Pilihan jenis prestasi tidak valid");
    }

    $code01 = trim($code01);
    if ($code01 !== "" && !kategoriVisibleForUnit(trim((string) ($row["kategori_code01"] ?? "")), $code01)) {
        fail(422, "Jenis prestasi tidak tersedia untuk unit ini");
    }

    $label = trim((string) $row["kategori_nama"]) . " — " . trim((string) $row["tingkat_nama"]) . " — " . trim((string) $row["poin_nama"]);
    $label = secure_validate_text_field($label, 150) ?? substr($label, 0, 150);
    $nilai = secure_validate_nilai_penghargaan((string) ($row["nilai"] ?? "0"));
    if ($nilai === null) {
        $nilai = "0.00";
    }

    return [
        "jenis_prestasi" => $label,
        "nilai_penghargaan" => $nilai,
        "prestasi_kategori_id" => (int) $row["kategori_id"],
        "prestasi_tingkat_id" => (int) $row["tingkat_id"],
        "prestasi_poin_id" => (int) $row["poin_id"],
    ];
}

function assertTahunAkademikExists(PDO $pdo, string $tahun): void
{
    $stmt = $pdo->prepare("SELECT 1 FROM mst_thn_aka WHERE thn_aka = :tahun LIMIT 1");
    $stmt->bindValue(":tahun", $tahun, PDO::PARAM_STR);
    $stmt->execute();
    if (!$stmt->fetchColumn()) {
        fail(422, "Tahun akademik tidak valid");
    }
}

function allowedUploadHosts(): array
{
    $hosts = [];
    $base = trim((string) ($_ENV["PUBLIC_BASE_URL"] ?? ""));
    if ($base !== "") {
        $host = parse_url($base, PHP_URL_HOST);
        if (is_string($host) && $host !== "") {
            $hosts[] = $host;
        }
    }
    $laravel = trim((string) ($_ENV["LARAVEL_APP_URL"] ?? ""));
    if ($laravel !== "") {
        $host = parse_url($laravel, PHP_URL_HOST);
        if (is_string($host) && $host !== "") {
            $hosts[] = $host;
        }
    }
    return array_values(array_unique($hosts));
}

function assertSiswaSession(array $auth): array
{
    $custId = (string) ($auth["custid"] ?? "");
    $nocust = (string) ($auth["nocust"] ?? "");
    $nmcust = (string) ($auth["nmcust"] ?? "");
    $kelas  = (string) ($auth["kelas"] ?? "");

    if ($custId === "" || $nocust === "" || !secure_validate_nocust($nocust)) {
        writeLog("SISWA_INVALID_SESSION", ["custid" => $custId, "nocust" => $nocust]);
        fail(401, "Sesi tidak valid, silakan login ulang");
    }

    return [
        "custid" => $custId,
        "nocust" => $nocust,
        "nmcust" => $nmcust,
        "kelas" => $kelas,
    ];
}

function mapSiswaPrestasiRow(array $row): array
{
    $status = normalizeRewardApprovalStatus($row["isapproved"] ?? "pending");
    $catatan = trim((string) ($row["catatan_admin"] ?? ""));
    $nilai = secure_validate_nilai_penghargaan((string) ($row["nilai_penghargaan"] ?? "0"));
    if ($nilai === null) {
        $nilai = "0.00";
    }

    return [
        "id" => (int) ($row["id"] ?? 0),
        "nisn" => (string) ($row["nisn"] ?? ""),
        "jenis_prestasi" => (string) ($row["jenis_prestasi"] ?? ""),
        "prestasi_kategori_id" => (int) ($row["prestasi_kategori_id"] ?? 0),
        "prestasi_tingkat_id" => (int) ($row["prestasi_tingkat_id"] ?? 0),
        "prestasi_poin_id" => (int) ($row["prestasi_poin_id"] ?? 0),
        "keterangan" => (string) ($row["keterangan"] ?? ""),
        "penyelenggara" => (string) ($row["penyelenggara"] ?? ""),
        "no_sertifikat" => (string) ($row["no_sertifikat"] ?? ""),
        "nilai_penghargaan" => $nilai,
        "tahun_akademik" => (string) ($row["bta"] ?? ""),
        "semester" => (int) ($row["semester"] ?? 1),
        "url" => (string) ($row["url"] ?? ""),
        "isapproved" => $status,
        "catatan_admin" => $status === "canceled" ? $catatan : "",
        "can_edit" => $status === "canceled",
        "created_at" => (string) ($row["created_at"] ?? ""),
        "updated_at" => (string) ($row["updated_at"] ?? ""),
    ];
}

function doGetPrestasiSaya(array $auth): array
{
    $siswa = assertSiswaSession($auth);
    $pdo = dbConnectPdo();
    ensureCatatanAdminColumn($pdo);

    $sql = "
        SELECT
            ar.id,
            ar.nisn,
            ar.jenis_prestasi,
            ar.prestasi_kategori_id,
            ar.prestasi_tingkat_id,
            ar.prestasi_poin_id,
            ar.keterangan,
            ar.penyelenggara,
            ar.no_sertifikat,
            ar.nilai_penghargaan,
            ar.bta,
            ar.semester,
            ar.url,
            ar.isapproved,
            ar.catatan_admin,
            ar.created_at,
            ar.updated_at
        FROM aka_reward ar
        WHERE ar.custid = :custid AND ar.nocust = :nocust
        ORDER BY ar.created_at DESC, ar.id DESC
        LIMIT 200
    ";
    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(":custid", $siswa["custid"], PDO::PARAM_STR);
    $stmt->bindValue(":nocust", $siswa["nocust"], PDO::PARAM_STR);
    $stmt->execute();

    $items = [];
    $jumlah = ["pending" => 0, "approve" => 0, "canceled" => 0];
    foreach ($stmt->fetchAll() ?: [] as $row) {
        $item = mapSiswaPrestasiRow($row);
        $items[] = $item;
        if (isset($jumlah[$item["isapproved"]])) {
            $jumlah[$item["isapproved"]]++;
        }
    }

    $sumStmt = $pdo->prepare("
        SELECT COALESCE(SUM(nilai_penghargaan), 0)
        FROM aka_reward
        WHERE custid = :custid AND nocust = :nocust AND isapproved = 'approve'
    ");
    $sumStmt->bindValue(":custid", $siswa["custid"], PDO::PARAM_STR);
    $sumStmt->bindValue(":nocust", $siswa["nocust"], PDO::PARAM_STR);
    $sumStmt->execute();
    $total = secure_validate_nilai_penghargaan((string) $sumStmt->fetchColumn());
    if ($total === null) {
        $total = "0.00";
    }

    return [
        "items" => $items,
        "total_skor" => $total,
        "jumlah" => $jumlah,
    ];
}

function assertOwnedCanceledReward(PDO $pdo, int $id, string $custId, string $nocust): void
{
    $stmt = $pdo->prepare("
        SELECT isapproved FROM aka_reward
        WHERE id = :id AND custid = :custid AND nocust = :nocust
        LIMIT 1
    ");
    $stmt->bindValue(":id", $id, PDO::PARAM_INT);
    $stmt->bindValue(":custid", $custId, PDO::PARAM_STR);
    $stmt->bindValue(":nocust", $nocust, PDO::PARAM_STR);
    $stmt->execute();
    $row = $stmt->fetch();
    if (!$row) {
        fail(404, "Pengajuan tidak ditemukan");
    }
    if (normalizeRewardApprovalStatus($row["isapproved"] ?? "") !== "canceled") {
        fail(422, "Hanya pengajuan yang ditolak yang bisa dikirim ulang");
    }
}

function doSubmitPrestasi(array $req, array $auth): array
{
    $fields = validatePrestasiInput($req);
    $siswa = assertSiswaSession($auth);
    $custId = $siswa["custid"];
    $nocust = $siswa["nocust"];
    $nmcust = $siswa["nmcust"];
    $kelas = $siswa["kelas"];

    $editId = secure_validate_positive_id((string) ($req["id"] ?? ""));

    $pdo = dbConnectPdo();
    ensureAutoIncrementInsert($pdo);
    ensureCatatanAdminColumn($pdo);
    assertTahunAkademikExists($pdo, $fields["tahun_akademik"]);
    $code01 = trim((string) ($auth["code01"] ?? ""));
    if ($code01 === "") {
        $code01 = fetchSiswaCode01ByCustId($pdo, $custId);
    }
    $selection = fetchPrestasiSelection(
        $pdo,
        $fields["prestasi_kategori_id"],
        $fields["prestasi_tingkat_id"],
        $fields["prestasi_poin_id"],
        $code01
    );

    $url = $fields["url"];

    if ($editId !== null) {
        assertOwnedCanceledReward($pdo, $editId, $custId, $nocust);
        $sql = "
            UPDATE aka_reward
            SET nmcust = :nmcust,
                kelas = :kelas,
                nisn = :nisn,
                jenis_prestasi = :jenis,
                prestasi_kategori_id = :kategori,
                prestasi_tingkat_id = :tingkat,
                prestasi_poin_id = :poin,
                keterangan = :keterangan,
                penyelenggara = :penyelenggara,
                no_sertifikat = :sertifikat,
                nilai_penghargaan = :nilai,
                bta = :bta,
                semester = :semester,
                url = :url,
                isapproved = 'pending',
                approveddate = NULL,
                approvedby = NULL,
                catatan_admin = NULL,
                updated_at = NOW()
            WHERE id = :id AND custid = :custid AND nocust = :nocust
            LIMIT 1
        ";
        try {
            $stmt = $pdo->prepare($sql);
            $stmt->bindValue(":nmcust", $nmcust, PDO::PARAM_STR);
            $stmt->bindValue(":kelas", $kelas, PDO::PARAM_STR);
            $stmt->bindValue(":nisn", $fields["nisn"], PDO::PARAM_STR);
            $stmt->bindValue(":jenis", $selection["jenis_prestasi"], PDO::PARAM_STR);
            $stmt->bindValue(":kategori", $selection["prestasi_kategori_id"], PDO::PARAM_INT);
            $stmt->bindValue(":tingkat", $selection["prestasi_tingkat_id"], PDO::PARAM_INT);
            $stmt->bindValue(":poin", $selection["prestasi_poin_id"], PDO::PARAM_INT);
            $stmt->bindValue(":keterangan", $fields["keterangan"], PDO::PARAM_STR);
            $stmt->bindValue(":penyelenggara", $fields["penyelenggara"], PDO::PARAM_STR);
            $stmt->bindValue(":sertifikat", $fields["no_sertifikat"], PDO::PARAM_STR);
            $stmt->bindValue(":nilai", $selection["nilai_penghargaan"], PDO::PARAM_STR);
            $stmt->bindValue(":bta", $fields["tahun_akademik"], PDO::PARAM_STR);
            $stmt->bindValue(":semester", $fields["semester"], PDO::PARAM_INT);
            $stmt->bindValue(":url", $url, PDO::PARAM_STR);
            $stmt->bindValue(":id", $editId, PDO::PARAM_INT);
            $stmt->bindValue(":custid", $custId, PDO::PARAM_STR);
            $stmt->bindValue(":nocust", $nocust, PDO::PARAM_STR);
            $stmt->execute();
        } catch (PDOException $e) {
            $sqlMsg = $e->getMessage();
            writeLog("RESUBMIT_SQL_FAIL", ["sqlstate" => $e->getCode(), "message" => $sqlMsg]);
            if (str_contains($sqlMsg, "Unknown column")) {
                fail(500, "Kolom aka_reward belum lengkap. Jalankan query ALTER di Navicat.");
            }
            fail(500, "Gagal mengirim ulang prestasi.");
        }
        writeLog("RESUBMIT_SUCCESS", ["id" => $editId, "custid" => $custId, "nocust" => $nocust]);
        return [
            "id" => $editId,
            "url" => $url,
            "isapproved" => "pending",
        ];
    }

    $rewardId = allocateRewardId($pdo);

    $sql = "
        INSERT INTO aka_reward
            (id, custid, nocust, nmcust, kelas, nisn, jenis_prestasi, prestasi_kategori_id, prestasi_tingkat_id, prestasi_poin_id, keterangan, penyelenggara, no_sertifikat, nilai_penghargaan, bta, semester, url, isapproved, approveddate, approvedby, created_at, updated_at)
        VALUES
            (:id, :custid, :nocust, :nmcust, :kelas, :nisn, :jenis, :kategori, :tingkat, :poin, :keterangan, :penyelenggara, :sertifikat, :nilai, :bta, :semester, :url, 'pending', NULL, NULL, NOW(), NOW())
    ";

    try {
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(":id", $rewardId, PDO::PARAM_INT);
        $stmt->bindValue(":custid", $custId, PDO::PARAM_STR);
        $stmt->bindValue(":nocust", $nocust, PDO::PARAM_STR);
        $stmt->bindValue(":nmcust", $nmcust, PDO::PARAM_STR);
        $stmt->bindValue(":kelas", $kelas, PDO::PARAM_STR);
        $stmt->bindValue(":nisn", $fields["nisn"], PDO::PARAM_STR);
        $stmt->bindValue(":jenis", $selection["jenis_prestasi"], PDO::PARAM_STR);
        $stmt->bindValue(":kategori", $selection["prestasi_kategori_id"], PDO::PARAM_INT);
        $stmt->bindValue(":tingkat", $selection["prestasi_tingkat_id"], PDO::PARAM_INT);
        $stmt->bindValue(":poin", $selection["prestasi_poin_id"], PDO::PARAM_INT);
        $stmt->bindValue(":keterangan", $fields["keterangan"], PDO::PARAM_STR);
        $stmt->bindValue(":penyelenggara", $fields["penyelenggara"], PDO::PARAM_STR);
        $stmt->bindValue(":sertifikat", $fields["no_sertifikat"], PDO::PARAM_STR);
        $stmt->bindValue(":nilai", $selection["nilai_penghargaan"], PDO::PARAM_STR);
        $stmt->bindValue(":bta", $fields["tahun_akademik"], PDO::PARAM_STR);
        $stmt->bindValue(":semester", $fields["semester"], PDO::PARAM_INT);
        $stmt->bindValue(":url", $url, PDO::PARAM_STR);
        $stmt->execute();
    } catch (PDOException $e) {
        $sqlMsg = $e->getMessage();
        writeLog("SUBMIT_SQL_FAIL", ["sqlstate" => $e->getCode(), "message" => $sqlMsg]);
        if (str_contains($sqlMsg, "Unknown column")) {
            fail(500, "Kolom aka_reward belum lengkap. Jalankan query ALTER di Navicat (ws/sql/alter_aka_reward_kolom_prestasi.sql).");
        }
        if (str_contains($sqlMsg, "Incorrect integer") || str_contains(strtolower($sqlMsg), "isapproved")) {
            fail(500, "Kolom isapproved belum ENUM pending/approve/canceled. Jalankan ws/sql/aka_reward_approval_status.sql");
        }
        if (str_contains($sqlMsg, "Data too long")) {
            fail(422, "Salah satu isian terlalu panjang, terutama tautan Google Drive.");
        }
        fail(500, "Gagal menyimpan prestasi. Periksa tabel aka_reward.");
    }
    writeLog("SUBMIT_SUCCESS", ["id" => $rewardId, "custid" => $custId, "nocust" => $nocust, "tahun" => $fields["tahun_akademik"], "semester" => $fields["semester"], "poin_id" => $selection["prestasi_poin_id"]]);

    return [
        "id"  => fetchLastRewardInsertId($pdo, $custId, $nocust, $rewardId),
        "url" => $url,
    ];
}

function doGetTahunAkademik(): array
{
    $pdo = dbConnectPdo();
    $stmt = $pdo->prepare("SELECT thn_aka FROM mst_thn_aka ORDER BY urut ASC");
    $stmt->execute();
    $rows = $stmt->fetchAll();

    $result = [];
    foreach ($rows as $row) {
        $value = trim((string) ($row["thn_aka"] ?? ""));
        if ($value !== "") {
            $result[] = $value;
        }
    }

    return ["tahun_akademik" => $result];
}

function doGetPrestasiKatalog(array $req = []): array
{
    try {
        $pdo = dbConnectPdo();
        $data = fetchKatalogPayload($pdo);
        $code01 = resolveSiswaKatalogCode01($pdo, $req);
        $data = filterKatalogByUnit($data, $code01);
    } catch (Throwable) {
        fail(500, "Katalog prestasi belum siap. Jalankan query master di database.");
    }

    return [
        "kategori" => $data["kategori"],
        "tingkat" => $data["tingkat"],
        "poin" => $data["poin"],
    ];
}

loadEnv(__DIR__ . "/.env");

header("Content-Type: application/json; charset=utf-8");

$corsOrigin = (string) ($_ENV["CORS_ORIGIN"] ?? getenv("CORS_ORIGIN") ?: "*");
header("Access-Control-Allow-Origin: " . $corsOrigin);
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Credentials: true");

if (($_SERVER["REQUEST_METHOD"] ?? "") === "OPTIONS") {
    http_response_code(204);
    exit;
}

try {
    $req = getJsonInput();
    if (empty($req) && !empty($_POST)) {
        $req = $_POST;
    }

    $method = secure_validate_method(trim((string) ($req["method"] ?? "")));
    if ($method === null) {
        fail(422, "Permintaan tidak valid");
    }

    if ($method === "login") {
        writeLog("METHOD_LOGIN");
        $data = doLogin($req);
        http_response_code(200);
        echo json_encode(["status" => 200, "data" => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    if ($method === "loginApproval") {
        writeLog("METHOD_LOGIN_APPROVAL");
        $data = doLoginApproval($req);
        http_response_code(200);
        echo json_encode(["status" => 200, "data" => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    if ($method === "getTahunAkademik") {
        writeLog("METHOD_GET_TAHUN");
        $data = doGetTahunAkademik();
        http_response_code(200);
        echo json_encode(["status" => 200, "data" => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    if ($method === "getPrestasiKatalog") {
        writeLog("METHOD_GET_PRESTASI_KATALOG");
        $data = doGetPrestasiKatalog($req);
        http_response_code(200);
        echo json_encode(["status" => 200, "data" => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    $token = null;
    if (isset($req["token"]) && is_string($req["token"]) && $req["token"] !== "") {
        $token = $req["token"];
    } elseif (isset($_SERVER["HTTP_AUTHORIZATION"])) {
        $authHeader = $_SERVER["HTTP_AUTHORIZATION"];
        if (preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            $token = $matches[1];
        }
    }

    if (!$token || !secure_validate_token_format($token)) {
        fail(401, "Token wajib diisi");
    }

    $jwt = new JWT();
    $key = (string) ($_ENV["JWT_KEY"] ?? "");
    if ($key === "") {
        failSystem(500);
    }

    try {
        $decoded = $jwt->decode($token, $key, ["HS256"]);
        if (is_object($decoded)) $decoded = (array) $decoded;
    } catch (Throwable $e) {
        fail(401, "Token JWT tidak valid");
    }

    if ($method === "getPrestasiSaya") {
        writeLog("METHOD_GET_PRESTASI_SAYA");
        $data = doGetPrestasiSaya($decoded);
        http_response_code(200);
        echo json_encode(["status" => 200, "data" => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    if ($method === "submitPrestasi") {
        writeLog("METHOD_SUBMIT", ["has_file" => isset($_FILES["file"]), "id" => (string) ($req["id"] ?? "")]);
        $data = doSubmitPrestasi($req, $decoded);
        http_response_code(200);
        echo json_encode(["status" => 200, "data" => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    if ($method === "approval") {
        writeLog("METHOD_APPROVAL", ["action" => (string) ($req["action"] ?? "list")]);
        $data = doApproval($req, $decoded);
        http_response_code(200);
        echo json_encode(["status" => 200, "data" => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    if ($method === "manageUsers") {
        writeLog("METHOD_MANAGE_USERS", ["action" => (string) ($req["action"] ?? "list")]);
        $data = doManageUsers($req, $decoded);
        http_response_code(200);
        echo json_encode(["status" => 200, "data" => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    if ($method === "manageKatalog") {
        writeLog("METHOD_MANAGE_KATALOG", [
            "action" => (string) ($req["action"] ?? "list"),
            "entity" => (string) ($req["entity"] ?? ""),
        ]);
        $data = doManageKatalog($req, $decoded);
        http_response_code(200);
        echo json_encode(["status" => 200, "data" => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    fail(422, "Permintaan tidak valid");
} catch (Throwable $e) {
    writeLog("FATAL_EXCEPTION", ["message" => $e->getMessage(), "file" => $e->getFile(), "line" => $e->getLine()]);
    if ($e->getMessage() === "DB_UNAVAILABLE") {
        fail(503, "Tidak dapat terhubung ke database. Periksa jaringan atau VPN.");
    }
    failSystem(500);
}
