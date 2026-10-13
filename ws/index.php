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

const SECURE_INPUT_ALLOWED_METHODS = ['login', 'loginApproval', 'getTahunAkademik', 'getPrestasiKatalog', 'getPrestasiSaya', 'submitPrestasi', 'approval', 'manageUsers', 'manageKatalog', 'searchSiswa', 'manageCatatanKepribadian', 'manageTahfid'];

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
        WHERE LOWER(TRIM(u.username)) = LOWER(:username)
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
    return $role === 'musrifah' || $role === 'musyrifah' || $role === 'superadmin';
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

function ensureCatatanKepribadianTable(PDO $pdo): void
{
    static $ready = false;
    if ($ready) {
        return;
    }
    try {
        $pdo->query("SELECT id FROM aka_catatan_kepribadian LIMIT 0");
        $ready = true;
        return;
    } catch (Throwable) {
        // Tabel belum ada.
    }
    try {
        $pdo->exec("
            CREATE TABLE aka_catatan_kepribadian (
                id INT UNSIGNED NOT NULL AUTO_INCREMENT,
                custid VARCHAR(50) NOT NULL,
                nocust VARCHAR(50) NOT NULL,
                nmcust VARCHAR(150) NOT NULL DEFAULT '',
                kelas VARCHAR(80) NOT NULL DEFAULT '',
                code01 VARCHAR(20) NOT NULL DEFAULT '',
                bta VARCHAR(20) NOT NULL,
                semester TINYINT NOT NULL DEFAULT 1,
                jenis_pelanggaran VARCHAR(500) NOT NULL,
                bentuk_pembinaan VARCHAR(500) NOT NULL,
                skor DECIMAL(12,2) NOT NULL DEFAULT 0.00,
                created_by VARCHAR(50) NOT NULL DEFAULT '',
                updated_by VARCHAR(50) NOT NULL DEFAULT '',
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                KEY idx_nocust (nocust),
                KEY idx_bta_sem (bta, semester),
                KEY idx_code01 (code01)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");
        $ready = true;
    } catch (Throwable $e) {
        $msg = $e->getMessage();
        if (stripos($msg, "already exists") !== false) {
            $ready = true;
            return;
        }
        writeLog("CATATAN_KEPRIBADIAN_CREATE_FAIL", ["message" => $msg]);
        fail(500, "Tabel aka_catatan_kepribadian belum ada. Jalankan ws/sql/aka_catatan_kepribadian.sql");
    }
}

function staffUnitCode01(array $auth): string
{
    return isSuperadminRole((string) ($auth["role"] ?? ""))
        ? ""
        : trim((string) ($auth["code01"] ?? ""));
}

function fetchTahunAkademikList(PDO $pdo): array
{
    $rows = [];
    try {
        $stmt = $pdo->prepare("SELECT thn_aka FROM mst_thn_aka ORDER BY urut ASC");
        $stmt->execute();
        $rows = $stmt->fetchAll() ?: [];
    } catch (Throwable) {
        try {
            $stmt = $pdo->query("SELECT thn_aka FROM mst_thn_aka");
            $rows = $stmt ? ($stmt->fetchAll() ?: []) : [];
        } catch (Throwable) {
            return [];
        }
    }
    $result = [];
    foreach ($rows as $row) {
        $value = trim((string) ($row["thn_aka"] ?? ""));
        if ($value !== "") {
            $result[] = $value;
        }
    }
    return $result;
}

function fetchScopeSekolahName(PDO $pdo, string $code01): string
{
    $code01 = trim($code01);
    if ($code01 === "") {
        return "";
    }
    $stmt = $pdo->prepare("SELECT DESC01 FROM mst_sekolah WHERE CODE01 = :code01 LIMIT 1");
    $stmt->bindValue(":code01", $code01, PDO::PARAM_STR);
    $stmt->execute();
    return trim((string) ($stmt->fetchColumn() ?: ""));
}

function fetchSiswaByNocust(PDO $pdo, string $nocust, string $userCode01): ?array
{
    $sql = "
        SELECT
            TRIM(c.CUSTID) AS custid,
            TRIM(c.NOCUST) AS nocust,
            TRIM(c.NMCUST) AS nmcust,
            TRIM(c.DESC02) AS kelas,
            TRIM(c.CODE01) AS code01,
            TRIM(ms.DESC01) AS sekolah
        FROM scctcust c
        LEFT JOIN mst_sekolah ms ON ms.CODE01 = c.CODE01
        WHERE TRIM(c.NOCUST) = :nocust
          AND (:code01_empty = '' OR c.CODE01 = :code01_value)
        LIMIT 1
    ";
    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(":nocust", $nocust, PDO::PARAM_STR);
    $stmt->bindValue(":code01_empty", $userCode01, PDO::PARAM_STR);
    $stmt->bindValue(":code01_value", $userCode01, PDO::PARAM_STR);
    $stmt->execute();
    $row = $stmt->fetch();
    return $row ?: null;
}

function mapCatatanKepribadianRow(array $row): array
{
    return [
        "id" => (int) ($row["id"] ?? 0),
        "custid" => trim((string) ($row["custid"] ?? "")),
        "nocust" => trim((string) ($row["nocust"] ?? "")),
        "nmcust" => trim((string) ($row["nmcust"] ?? "")),
        "kelas" => trim((string) ($row["kelas"] ?? "")),
        "code01" => trim((string) ($row["code01"] ?? "")),
        "sekolah" => trim((string) ($row["sekolah"] ?? "")),
        "bta" => trim((string) ($row["bta"] ?? "")),
        "semester" => (string) ((int) ($row["semester"] ?? 1)),
        "jenis_pelanggaran" => trim((string) ($row["jenis_pelanggaran"] ?? "")),
        "bentuk_pembinaan" => trim((string) ($row["bentuk_pembinaan"] ?? "")),
        "skor" => number_format((float) ($row["skor"] ?? 0), 2, ".", ""),
        "created_by" => trim((string) ($row["created_by"] ?? "")),
        "updated_by" => trim((string) ($row["updated_by"] ?? "")),
        "created_at" => trim((string) ($row["created_at"] ?? "")),
        "updated_at" => trim((string) ($row["updated_at"] ?? "")),
    ];
}

function doSearchSiswa(array $req, array $auth): array
{
    assertApprovalRole($auth);
    $q = trim((string) ($req["q"] ?? ""));
    if (mb_strlen($q) < 2 || mb_strlen($q) > 80) {
        fail(422, "Kata kunci pencarian minimal 2 karakter");
    }

    $pdo = dbConnectPdo();
    $userCode01 = staffUnitCode01($auth);
    $like = "%" . str_replace(["\\", "%", "_"], ["\\\\", "\\%", "\\_"], $q) . "%";
    $sql = "
        SELECT
            TRIM(c.CUSTID) AS custid,
            TRIM(c.NOCUST) AS nocust,
            TRIM(c.NMCUST) AS nmcust,
            TRIM(c.DESC02) AS kelas,
            TRIM(c.CODE01) AS code01,
            TRIM(ms.DESC01) AS sekolah
        FROM scctcust c
        LEFT JOIN mst_sekolah ms ON ms.CODE01 = c.CODE01
        WHERE (c.NOCUST LIKE :q1 OR c.NMCUST LIKE :q2)
          AND (:code01_empty = '' OR c.CODE01 = :code01_value)
        ORDER BY c.NMCUST ASC
        LIMIT 20
    ";
    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(":q1", $like, PDO::PARAM_STR);
    $stmt->bindValue(":q2", $like, PDO::PARAM_STR);
    $stmt->bindValue(":code01_empty", $userCode01, PDO::PARAM_STR);
    $stmt->bindValue(":code01_value", $userCode01, PDO::PARAM_STR);
    $stmt->execute();
    $rows = $stmt->fetchAll() ?: [];
    $items = [];
    foreach ($rows as $row) {
        if (!is_array($row)) {
            continue;
        }
        $nocust = trim((string) ($row["nocust"] ?? ""));
        if ($nocust === "" || !secure_validate_nocust($nocust)) {
            continue;
        }
        $items[] = [
            "custid" => trim((string) ($row["custid"] ?? "")),
            "nocust" => $nocust,
            "nmcust" => trim((string) ($row["nmcust"] ?? "")),
            "kelas" => trim((string) ($row["kelas"] ?? "")),
            "code01" => trim((string) ($row["code01"] ?? "")),
            "sekolah" => trim((string) ($row["sekolah"] ?? "")),
        ];
    }

    return ["items" => $items];
}

function doManageCatatanKepribadian(array $req, array $auth): array
{
    assertApprovalRole($auth);
    $action = strtolower(trim((string) ($req["action"] ?? "list")));
    if (!in_array($action, ["list", "get", "create", "update", "delete"], true)) {
        fail(422, "Aksi catatan tidak valid");
    }

    $pdo = dbConnectPdo();
    ensureCatatanKepribadianTable($pdo);
    $userCode01 = staffUnitCode01($auth);

    if ($action === "list") {
        $q = trim((string) ($req["q"] ?? ""));
        $bta = trim((string) ($req["bta"] ?? ""));
        $semester = trim((string) ($req["semester"] ?? ""));
        $sql = "
            SELECT
                ck.id, ck.custid, ck.nocust, ck.nmcust, ck.kelas, ck.code01,
                ms.DESC01 AS sekolah, ck.bta, ck.semester, ck.jenis_pelanggaran,
                ck.bentuk_pembinaan, ck.skor, ck.created_by, ck.updated_by,
                ck.created_at, ck.updated_at
            FROM aka_catatan_kepribadian ck
            LEFT JOIN mst_sekolah ms ON ms.CODE01 = ck.code01
            WHERE (:code01_empty = '' OR ck.code01 = :code01_value)
        ";
        if ($q !== "") {
            $sql .= " AND (ck.nocust LIKE :q_nis OR ck.nmcust LIKE :q_nama) ";
        }
        if ($bta !== "") {
            $sql .= " AND ck.bta = :bta ";
        }
        if ($semester === "1" || $semester === "2") {
            $sql .= " AND ck.semester = :semester ";
        }
        $sql .= " ORDER BY ck.created_at DESC, ck.id DESC LIMIT 1000 ";
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(":code01_empty", $userCode01, PDO::PARAM_STR);
        $stmt->bindValue(":code01_value", $userCode01, PDO::PARAM_STR);
        if ($q !== "") {
            $like = "%" . str_replace(["\\", "%", "_"], ["\\\\", "\\%", "\\_"], $q) . "%";
            $stmt->bindValue(":q_nis", $like, PDO::PARAM_STR);
            $stmt->bindValue(":q_nama", $like, PDO::PARAM_STR);
        }
        if ($bta !== "") {
            $stmt->bindValue(":bta", $bta, PDO::PARAM_STR);
        }
        if ($semester === "1" || $semester === "2") {
            $stmt->bindValue(":semester", (int) $semester, PDO::PARAM_INT);
        }
        try {
            $stmt->execute();
        } catch (Throwable $e) {
            writeLog("CATATAN_KEPRIBADIAN_LIST_FAIL", ["message" => $e->getMessage()]);
            fail(500, "Tabel aka_catatan_kepribadian belum siap. Jalankan ws/sql/aka_catatan_kepribadian.sql");
        }
        $rows = $stmt->fetchAll() ?: [];
        $items = [];
        foreach ($rows as $row) {
            if (is_array($row)) {
                $items[] = mapCatatanKepribadianRow($row);
            }
        }
        return [
            "items" => $items,
            "total" => count($items),
            "tahun_akademik" => fetchTahunAkademikList($pdo),
            "scope_code01" => $userCode01,
            "scope_sekolah" => fetchScopeSekolahName($pdo, $userCode01),
        ];
    }

    $by = approvalStaffUsername($auth);
    $id = (int) ($req["id"] ?? 0);
    if ($action === "get" || $action === "update" || $action === "delete") {
        if ($id <= 0) {
            fail(422, "ID catatan tidak valid");
        }
        $getSql = "
            SELECT
                ck.id, ck.custid, ck.nocust, ck.nmcust, ck.kelas, ck.code01,
                ms.DESC01 AS sekolah, ck.bta, ck.semester, ck.jenis_pelanggaran,
                ck.bentuk_pembinaan, ck.skor, ck.created_by, ck.updated_by,
                ck.created_at, ck.updated_at
            FROM aka_catatan_kepribadian ck
            LEFT JOIN mst_sekolah ms ON ms.CODE01 = ck.code01
            WHERE ck.id = :id
              AND (:code01_empty = '' OR ck.code01 = :code01_value)
            LIMIT 1
        ";
        $getStmt = $pdo->prepare($getSql);
        $getStmt->bindValue(":id", $id, PDO::PARAM_INT);
        $getStmt->bindValue(":code01_empty", $userCode01, PDO::PARAM_STR);
        $getStmt->bindValue(":code01_value", $userCode01, PDO::PARAM_STR);
        $getStmt->execute();
        $existing = $getStmt->fetch();
        if (!$existing) {
            fail(404, "Catatan tidak ditemukan atau di luar akses sekolah");
        }
        if ($action === "get") {
            return [
                "item" => mapCatatanKepribadianRow($existing),
                "tahun_akademik" => fetchTahunAkademikList($pdo),
                "scope_code01" => $userCode01,
                "scope_sekolah" => fetchScopeSekolahName($pdo, $userCode01),
            ];
        }
        if ($action === "delete") {
            $del = $pdo->prepare("DELETE FROM aka_catatan_kepribadian WHERE id = :id LIMIT 1");
            $del->bindValue(":id", $id, PDO::PARAM_INT);
            $del->execute();
            writeLog("CATATAN_KEPRIBADIAN_DELETE", ["id" => $id, "by" => $by]);
            return ["id" => $id, "message" => "Catatan berhasil dihapus"];
        }
    }

    $nis = trim((string) ($req["nis"] ?? ($req["nocust"] ?? "")));
    $tahun = secure_validate_tahun_akademik((string) ($req["tahun_akademik"] ?? ($req["bta"] ?? "")));
    $semester = secure_validate_semester((string) ($req["semester"] ?? ""));
    $jenis = secure_validate_text_field((string) ($req["jenis_pelanggaran"] ?? ""), 500, 3);
    $pembinaan = secure_validate_text_field((string) ($req["bentuk_pembinaan"] ?? ""), 500, 3);
    $skor = secure_validate_nilai_penghargaan((string) ($req["skor"] ?? ""));
    if ($nis === "" || !secure_validate_nocust($nis)) {
        fail(422, "NIS siswi tidak valid");
    }
    if ($tahun === null) {
        fail(422, "Tahun ajaran tidak valid");
    }
    if ($semester === null) {
        fail(422, "Semester tidak valid");
    }
    if ($jenis === null || $pembinaan === null) {
        fail(422, "Jenis pelanggaran dan bentuk pembinaan wajib diisi");
    }
    if ($skor === null) {
        fail(422, "Skor tidak valid");
    }
    assertTahunAkademikExists($pdo, $tahun);
    $siswa = fetchSiswaByNocust($pdo, $nis, $userCode01);
    if (!$siswa) {
        fail(422, "Siswi tidak ditemukan atau di luar akses sekolah");
    }

    if ($action === "create") {
        $ins = $pdo->prepare("
            INSERT INTO aka_catatan_kepribadian
                (custid, nocust, nmcust, kelas, code01, bta, semester, jenis_pelanggaran, bentuk_pembinaan, skor, created_by, updated_by, created_at, updated_at)
            VALUES
                (:custid, :nocust, :nmcust, :kelas, :code01, :bta, :semester, :jenis, :pembinaan, :skor, :created_by, :updated_by, NOW(), NOW())
        ");
        $ins->bindValue(":custid", (string) $siswa["custid"], PDO::PARAM_STR);
        $ins->bindValue(":nocust", (string) $siswa["nocust"], PDO::PARAM_STR);
        $ins->bindValue(":nmcust", (string) $siswa["nmcust"], PDO::PARAM_STR);
        $ins->bindValue(":kelas", (string) $siswa["kelas"], PDO::PARAM_STR);
        $ins->bindValue(":code01", (string) $siswa["code01"], PDO::PARAM_STR);
        $ins->bindValue(":bta", $tahun, PDO::PARAM_STR);
        $ins->bindValue(":semester", (int) $semester, PDO::PARAM_INT);
        $ins->bindValue(":jenis", $jenis, PDO::PARAM_STR);
        $ins->bindValue(":pembinaan", $pembinaan, PDO::PARAM_STR);
        $ins->bindValue(":skor", $skor, PDO::PARAM_STR);
        $ins->bindValue(":created_by", $by, PDO::PARAM_STR);
        $ins->bindValue(":updated_by", $by, PDO::PARAM_STR);
        $ins->execute();
        $newId = (int) $pdo->lastInsertId();
        writeLog("CATATAN_KEPRIBADIAN_CREATE", ["id" => $newId, "nocust" => $siswa["nocust"], "by" => $by]);
        return ["id" => $newId, "message" => "Catatan berhasil disimpan"];
    }

    $upd = $pdo->prepare("
        UPDATE aka_catatan_kepribadian
        SET custid = :custid, nocust = :nocust, nmcust = :nmcust, kelas = :kelas, code01 = :code01,
            bta = :bta, semester = :semester, jenis_pelanggaran = :jenis, bentuk_pembinaan = :pembinaan,
            skor = :skor, updated_by = :updated_by, updated_at = NOW()
        WHERE id = :id
        LIMIT 1
    ");
    $upd->bindValue(":custid", (string) $siswa["custid"], PDO::PARAM_STR);
    $upd->bindValue(":nocust", (string) $siswa["nocust"], PDO::PARAM_STR);
    $upd->bindValue(":nmcust", (string) $siswa["nmcust"], PDO::PARAM_STR);
    $upd->bindValue(":kelas", (string) $siswa["kelas"], PDO::PARAM_STR);
    $upd->bindValue(":code01", (string) $siswa["code01"], PDO::PARAM_STR);
    $upd->bindValue(":bta", $tahun, PDO::PARAM_STR);
    $upd->bindValue(":semester", (int) $semester, PDO::PARAM_INT);
    $upd->bindValue(":jenis", $jenis, PDO::PARAM_STR);
    $upd->bindValue(":pembinaan", $pembinaan, PDO::PARAM_STR);
    $upd->bindValue(":skor", $skor, PDO::PARAM_STR);
    $upd->bindValue(":updated_by", $by, PDO::PARAM_STR);
    $upd->bindValue(":id", $id, PDO::PARAM_INT);
    $upd->execute();
    writeLog("CATATAN_KEPRIBADIAN_UPDATE", ["id" => $id, "nocust" => $siswa["nocust"], "by" => $by]);
    return ["id" => $id, "message" => "Catatan berhasil diperbarui"];
}

function doGetTahunAkademik(): array
{
    return ["tahun_akademik" => fetchTahunAkademikList(dbConnectPdo())];
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

function quranSurahAyatCount(int $nomor): int
{
    static $counts = [
        7, 286, 200, 176, 120, 165, 206, 75, 129, 109, 123, 111, 43, 52, 99, 128, 111, 110, 98, 135,
        112, 78, 118, 64, 77, 227, 93, 88, 69, 60, 34, 30, 73, 54, 45, 83, 182, 88, 75, 85,
        54, 53, 89, 59, 37, 35, 38, 29, 18, 45, 60, 49, 62, 55, 78, 96, 29, 22, 24, 13,
        14, 11, 11, 18, 12, 12, 30, 52, 52, 44, 28, 28, 20, 56, 40, 31, 50, 40, 46, 42,
        29, 19, 36, 25, 22, 17, 19, 26, 30, 20, 15, 21, 11, 8, 8, 19, 5, 8, 8, 11,
        11, 8, 3, 9, 5, 4, 7, 3, 6, 3, 5, 4, 5, 6,
    ];
    if ($nomor < 1 || $nomor > 114) {
        return 0;
    }
    return (int) $counts[$nomor - 1];
}

function quranJuzForAyah(int $surah, int $ayah): int
{
    static $starts = [
        [1, 1, 1], [2, 2, 142], [3, 2, 253], [4, 3, 93], [5, 4, 24],
        [6, 4, 148], [7, 5, 82], [8, 6, 111], [9, 7, 88], [10, 8, 41],
        [11, 9, 93], [12, 11, 6], [13, 12, 53], [14, 15, 1], [15, 17, 1],
        [16, 18, 75], [17, 21, 1], [18, 23, 1], [19, 25, 21], [20, 27, 56],
        [21, 29, 46], [22, 33, 31], [23, 36, 28], [24, 39, 32], [25, 41, 47],
        [26, 46, 1], [27, 51, 31], [28, 58, 1], [29, 67, 1], [30, 78, 1],
    ];
    $juz = 1;
    foreach ($starts as $row) {
        [$j, $s, $a] = $row;
        if ($surah > $s || ($surah === $s && $ayah >= $a)) {
            $juz = $j;
        }
    }
    return $juz;
}

function tahfidIsSiswaAuth(array $auth): bool
{
    return trim((string) ($auth["custid"] ?? "")) !== "";
}

function tahfidJuzLabel(int $dari, int $sampai): string
{
    if ($dari === $sampai) {
        return "Juz " . $dari;
    }
    return "Juz " . $dari . "–" . $sampai;
}

function tahfidAyatLabel(bool $lengkap, int $dari, int $sampai): string
{
    if ($lengkap) {
        return "Lengkap (ayat " . $dari . "–" . $sampai . ")";
    }
    return "Ayat " . $dari . "–" . $sampai;
}

function ensureTahfidJadwalCode03(PDO $pdo): void
{
    static $ready = false;
    if ($ready) {
        return;
    }
    try {
        $pdo->query("SELECT code03 FROM aka_tahfid_jadwal LIMIT 0");
        $ready = true;
        return;
    } catch (Throwable) {
        // Kolom belum ada.
    }
    try {
        $pdo->exec("ALTER TABLE aka_tahfid_jadwal ADD COLUMN code03 VARCHAR(20) NOT NULL DEFAULT '' AFTER kelas");
        try {
            $pdo->exec("ALTER TABLE aka_tahfid_jadwal ADD KEY idx_code03 (code03)");
        } catch (Throwable) {
            // Index mungkin sudah ada.
        }
        $ready = true;
    } catch (Throwable $e) {
        if (stripos($e->getMessage(), "Duplicate") !== false) {
            $ready = true;
            return;
        }
        writeLog("TAHFID_CODE03_FAIL", ["message" => $e->getMessage()]);
        fail(500, "Kolom code03 pada aka_tahfid_jadwal belum ada. Jalankan ALTER di ws/sql/aka_tahfid.sql");
    }
}

function ensureTahfidProgressTables(PDO $pdo): void
{
    static $ready = false;
    if ($ready) {
        return;
    }
    try {
        $pdo->query("SELECT id, ayat_sampai, status, catatan FROM aka_tahfid_progress LIMIT 0");
        $pdo->query("SELECT id FROM aka_tahfid_progress_log LIMIT 0");
        $ready = true;
        return;
    } catch (Throwable) {
        // Tabel belum ada.
    }
    try {
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS aka_tahfid_progress (
                id INT UNSIGNED NOT NULL AUTO_INCREMENT,
                custid VARCHAR(50) NOT NULL,
                nocust VARCHAR(50) NOT NULL DEFAULT '',
                nmcust VARCHAR(150) NOT NULL DEFAULT '',
                code01 VARCHAR(20) NOT NULL DEFAULT '',
                kelas VARCHAR(80) NOT NULL DEFAULT '',
                jadwal_detail_id INT UNSIGNED NOT NULL,
                ayat_dari SMALLINT UNSIGNED NOT NULL DEFAULT 1,
                ayat_sampai SMALLINT UNSIGNED NOT NULL DEFAULT 1,
                status VARCHAR(20) NOT NULL DEFAULT 'proses',
                catatan TEXT NULL,
                created_by VARCHAR(50) NOT NULL DEFAULT '',
                updated_by VARCHAR(50) NOT NULL DEFAULT '',
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                UNIQUE KEY uk_siswa_detail_progress (custid, jadwal_detail_id),
                KEY idx_custid (custid),
                KEY idx_detail (jadwal_detail_id),
                KEY idx_status (status)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS aka_tahfid_progress_log (
                id INT UNSIGNED NOT NULL AUTO_INCREMENT,
                progress_id INT UNSIGNED NOT NULL,
                jadwal_detail_id INT UNSIGNED NOT NULL,
                custid VARCHAR(50) NOT NULL,
                ayat_dari SMALLINT UNSIGNED NOT NULL DEFAULT 1,
                ayat_sampai SMALLINT UNSIGNED NOT NULL DEFAULT 1,
                status VARCHAR(20) NOT NULL DEFAULT 'proses',
                catatan TEXT NULL,
                created_by VARCHAR(50) NOT NULL DEFAULT '',
                created_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                KEY idx_progress (progress_id),
                KEY idx_custid (custid),
                KEY idx_detail (jadwal_detail_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");
        $ready = true;
    } catch (Throwable $e) {
        writeLog("TAHFID_PROGRESS_CREATE_FAIL", ["message" => $e->getMessage()]);
        fail(500, "Tabel progress tahfid belum ada. Jalankan ws/sql/aka_tahfid.sql");
    }
}

function tahfidProgressStatusLabel(string $status): string
{
    return match ($status) {
        "lunas" => "Lunas",
        "proses" => "Proses",
        default => "Belum",
    };
}

function tahfidCoveredAyatLabel(array $covered, int $targetDari, int $targetSampai): string
{
    if (count($covered) === 0) {
        return "";
    }
    ksort($covered);
    $parts = [];
    $start = null;
    $prev = null;
    foreach (array_keys($covered) as $ayat) {
        $ayat = (int) $ayat;
        if ($start === null) {
            $start = $ayat;
            $prev = $ayat;
            continue;
        }
        if ($ayat === $prev + 1) {
            $prev = $ayat;
            continue;
        }
        $parts[] = $start === $prev ? (string) $start : ($start . "–" . $prev);
        $start = $ayat;
        $prev = $ayat;
    }
    if ($start !== null) {
        $parts[] = $start === $prev ? (string) $start : ($start . "–" . $prev);
    }
    $label = "Ayat " . implode(", ", $parts);
    if (count($covered) >= ($targetSampai - $targetDari + 1)) {
        return $label;
    }
    return $label;
}

function tahfidSummarizeCoverage(array $ranges, int $targetDari, int $targetSampai): array
{
    $covered = [];
    foreach ($ranges as $row) {
        $a = max($targetDari, (int) ($row["dari"] ?? $row["ayat_dari"] ?? 0));
        $b = min($targetSampai, (int) ($row["sampai"] ?? $row["ayat_sampai"] ?? 0));
        if ($b < $a) {
            continue;
        }
        for ($i = $a; $i <= $b; $i++) {
            $covered[$i] = true;
        }
    }
    $lunas = $targetSampai >= $targetDari;
    for ($i = $targetDari; $i <= $targetSampai; $i++) {
        if (!isset($covered[$i])) {
            $lunas = false;
            break;
        }
    }
    $min = 0;
    $max = 0;
    if (count($covered) > 0) {
        $min = (int) min(array_keys($covered));
        $max = (int) max(array_keys($covered));
    }
    $status = $lunas ? "lunas" : (count($covered) > 0 ? "proses" : "belum");
    return [
        "ayat_dari" => $min > 0 ? $min : $targetDari,
        "ayat_sampai" => $max > 0 ? $max : $targetDari,
        "status" => $status,
        "progress_label" => $status === "belum" ? "" : tahfidCoveredAyatLabel($covered, $targetDari, $targetSampai),
    ];
}

function tahfidFetchProgressLogs(PDO $pdo, string $custid, int $detailId, int $limit = 8): array
{
    $stmt = $pdo->prepare("
        SELECT ayat_dari, ayat_sampai, status, catatan, created_by, created_at
        FROM aka_tahfid_progress_log
        WHERE custid = :c AND jadwal_detail_id = :d
        ORDER BY id DESC
        LIMIT " . max(1, $limit) . "
    ");
    $stmt->bindValue(":c", $custid, PDO::PARAM_STR);
    $stmt->bindValue(":d", $detailId, PDO::PARAM_INT);
    $stmt->execute();
    $items = [];
    foreach ($stmt->fetchAll() ?: [] as $row) {
        if (!is_array($row)) {
            continue;
        }
        $items[] = [
            "ayat_dari" => (int) $row["ayat_dari"],
            "ayat_sampai" => (int) $row["ayat_sampai"],
            "ayat_label" => "Ayat " . (int) $row["ayat_dari"] . "–" . (int) $row["ayat_sampai"],
            "status" => trim((string) $row["status"]),
            "status_label" => tahfidProgressStatusLabel(trim((string) $row["status"])),
            "catatan" => trim((string) ($row["catatan"] ?? "")),
            "created_by" => trim((string) ($row["created_by"] ?? "")),
            "created_at" => trim((string) ($row["created_at"] ?? "")),
        ];
    }
    return $items;
}

function tahfidFetchAllProgressRanges(PDO $pdo, string $custid, int $detailId): array
{
    $stmt = $pdo->prepare("
        SELECT id, ayat_dari, ayat_sampai, status FROM aka_tahfid_progress_log
        WHERE custid = :c AND jadwal_detail_id = :d
        ORDER BY id ASC
    ");
    $stmt->bindValue(":c", $custid, PDO::PARAM_STR);
    $stmt->bindValue(":d", $detailId, PDO::PARAM_INT);
    $stmt->execute();
    $rows = [];
    foreach ($stmt->fetchAll() ?: [] as $row) {
        if (is_array($row)) {
            $rows[] = $row;
        }
    }
    return $rows;
}

function tahfidActiveRangesForStatus(array $logs, bool $forceLunas, int $newLogId): array
{
    $start = 0;
    if (!$forceLunas) {
        foreach ($logs as $i => $row) {
            $id = (int) ($row["id"] ?? 0);
            $st = trim((string) ($row["status"] ?? ""));
            if ($id !== $newLogId && $st === "lunas") {
                $start = $i + 1;
            }
        }
    }
    $ranges = [];
    $slice = array_slice($logs, $start);
    foreach ($slice as $row) {
        $ranges[] = [
            "dari" => (int) ($row["ayat_dari"] ?? 0),
            "sampai" => (int) ($row["ayat_sampai"] ?? 0),
        ];
    }
    return $ranges;
}

function tahfidClearSetoranIfNotLunas(PDO $pdo, string $custid, int $detailId, string $status): void
{
    if ($status === "lunas") {
        return;
    }
    $del = $pdo->prepare("DELETE FROM aka_tahfid_setoran WHERE custid = :c AND jadwal_detail_id = :d LIMIT 1");
    $del->bindValue(":c", $custid, PDO::PARAM_STR);
    $del->bindValue(":d", $detailId, PDO::PARAM_INT);
    $del->execute();
}

function tahfidMarkSetoranIfLunas(PDO $pdo, array $siswa, int $detailId, string $status): void
{
    if ($status !== "lunas") {
        return;
    }
    try {
        $ins = $pdo->prepare("
            INSERT INTO aka_tahfid_setoran
                (custid, nocust, nmcust, code01, kelas, jadwal_detail_id, status, created_at)
            VALUES
                (:custid, :nocust, :nmcust, :code01, :kelas, :did, 'setor', NOW())
        ");
        $ins->bindValue(":custid", (string) $siswa["custid"], PDO::PARAM_STR);
        $ins->bindValue(":nocust", (string) $siswa["nocust"], PDO::PARAM_STR);
        $ins->bindValue(":nmcust", (string) $siswa["nmcust"], PDO::PARAM_STR);
        $ins->bindValue(":code01", (string) $siswa["code01"], PDO::PARAM_STR);
        $ins->bindValue(":kelas", (string) $siswa["kelas"], PDO::PARAM_STR);
        $ins->bindValue(":did", $detailId, PDO::PARAM_INT);
        $ins->execute();
    } catch (Throwable $e) {
        if (stripos($e->getMessage(), "Duplicate") === false) {
            throw $e;
        }
    }
}

function tahfidSiswaBolehAksesDetail(PDO $pdo, array $siswa, array $detailRow): bool
{
    $code01 = trim((string) $siswa["code01"]);
    $kelas = trim((string) $siswa["kelas"]);
    $custid = trim((string) $siswa["custid"]);
    if (trim((string) $detailRow["code01"]) !== $code01) {
        return false;
    }
    $jadwalKelas = trim((string) $detailRow["kelas"]);
    if ($jadwalKelas === $kelas) {
        return true;
    }
    $cek = $pdo->prepare("SELECT id FROM aka_tahfid_percepatan WHERE custid = :c AND kelas_tujuan = :k LIMIT 1");
    $cek->bindValue(":c", $custid, PDO::PARAM_STR);
    $cek->bindValue(":k", $jadwalKelas, PDO::PARAM_STR);
    $cek->execute();
    return (int) ($cek->fetchColumn() ?: 0) > 0;
}

function tahfidUpsertProgress(
    PDO $pdo,
    array $siswa,
    int $detailId,
    int $ayatDari,
    int $ayatSampai,
    bool $forceLunas,
    string $catatan,
    string $by
): array {
    $detail = $pdo->prepare("
        SELECT d.id, d.ayat_dari, d.ayat_sampai, d.is_lengkap, d.surah_nomor, d.surah_nama, j.code01, j.kelas
        FROM aka_tahfid_jadwal_detail d
        INNER JOIN aka_tahfid_jadwal j ON j.id = d.jadwal_id
        WHERE d.id = :id
        LIMIT 1
    ");
    $detail->bindValue(":id", $detailId, PDO::PARAM_INT);
    $detail->execute();
    $row = $detail->fetch();
    if (!is_array($row)) {
        fail(404, "Item jadwal tidak ditemukan");
    }
    if (!tahfidSiswaBolehAksesDetail($pdo, $siswa, $row)) {
        fail(403, "Siswi ini tidak memiliki jadwal surat tersebut");
    }
    $targetDari = (int) ($row["ayat_dari"] ?? 1);
    $targetSampai = (int) ($row["ayat_sampai"] ?? $targetDari);
    if ($targetSampai < $targetDari) {
        $targetSampai = $targetDari;
    }
    if ($forceLunas) {
        $ayatDari = $targetDari;
        $ayatSampai = $targetSampai;
    }
    if ($ayatDari < $targetDari || $ayatSampai > $targetSampai || $ayatSampai < $ayatDari) {
        fail(422, "Rentang ayat harus di dalam target jadwal (ayat " . $targetDari . "–" . $targetSampai . ")");
    }
    $catatan = mb_substr(trim($catatan), 0, 500);
    $custid = trim((string) $siswa["custid"]);

    $find = $pdo->prepare("SELECT id, status FROM aka_tahfid_progress WHERE custid = :c AND jadwal_detail_id = :d LIMIT 1");
    $find->bindValue(":c", $custid, PDO::PARAM_STR);
    $find->bindValue(":d", $detailId, PDO::PARAM_INT);
    $find->execute();
    $existing = $find->fetch();
    $progressId = is_array($existing) ? (int) $existing["id"] : 0;

    if ($progressId < 1) {
        $ins = $pdo->prepare("
            INSERT INTO aka_tahfid_progress
                (custid, nocust, nmcust, code01, kelas, jadwal_detail_id, ayat_dari, ayat_sampai, status, catatan,
                 created_by, updated_by, created_at, updated_at)
            VALUES
                (:custid, :nocust, :nmcust, :code01, :kelas, :did, :ad, :as, 'proses', :cat,
                 :by1, :by2, NOW(), NOW())
        ");
        $ins->bindValue(":custid", $custid, PDO::PARAM_STR);
        $ins->bindValue(":nocust", (string) $siswa["nocust"], PDO::PARAM_STR);
        $ins->bindValue(":nmcust", (string) $siswa["nmcust"], PDO::PARAM_STR);
        $ins->bindValue(":code01", (string) $siswa["code01"], PDO::PARAM_STR);
        $ins->bindValue(":kelas", (string) $siswa["kelas"], PDO::PARAM_STR);
        $ins->bindValue(":did", $detailId, PDO::PARAM_INT);
        $ins->bindValue(":ad", $ayatDari, PDO::PARAM_INT);
        $ins->bindValue(":as", $ayatSampai, PDO::PARAM_INT);
        $ins->bindValue(":cat", $catatan, PDO::PARAM_STR);
        $ins->bindValue(":by1", $by, PDO::PARAM_STR);
        $ins->bindValue(":by2", $by, PDO::PARAM_STR);
        $ins->execute();
        $progressId = (int) $pdo->lastInsertId();
    }

    $log = $pdo->prepare("
        INSERT INTO aka_tahfid_progress_log
            (progress_id, jadwal_detail_id, custid, ayat_dari, ayat_sampai, status, catatan, created_by, created_at)
        VALUES
            (:pid, :did, :custid, :ad, :as, 'proses', :cat, :by, NOW())
    ");
    $log->bindValue(":pid", $progressId, PDO::PARAM_INT);
    $log->bindValue(":did", $detailId, PDO::PARAM_INT);
    $log->bindValue(":custid", $custid, PDO::PARAM_STR);
    $log->bindValue(":ad", $ayatDari, PDO::PARAM_INT);
    $log->bindValue(":as", $ayatSampai, PDO::PARAM_INT);
    $log->bindValue(":cat", $catatan, PDO::PARAM_STR);
    $log->bindValue(":by", $by, PDO::PARAM_STR);
    $log->execute();
    $logId = (int) $pdo->lastInsertId();

    $logs = tahfidFetchAllProgressRanges($pdo, $custid, $detailId);
    $summary = tahfidSummarizeCoverage(
        tahfidActiveRangesForStatus($logs, $forceLunas, $logId),
        $targetDari,
        $targetSampai
    );
    if ($forceLunas) {
        $summary["status"] = "lunas";
        $summary["ayat_dari"] = $targetDari;
        $summary["ayat_sampai"] = $targetSampai;
        $summary["progress_label"] = tahfidAyatLabel(true, $targetDari, $targetSampai);
    } else {
        $summary["status"] = "proses";
        $summary["ayat_dari"] = $ayatDari;
        $summary["ayat_sampai"] = $ayatSampai;
        $summary["progress_label"] = "Ayat " . $ayatDari . "–" . $ayatSampai;
    }

    $upd = $pdo->prepare("
        UPDATE aka_tahfid_progress
        SET ayat_dari = :ad, ayat_sampai = :as, status = :st, catatan = :cat,
            nocust = :nocust, nmcust = :nmcust, code01 = :code01, kelas = :kelas,
            updated_by = :by, updated_at = NOW()
        WHERE id = :id LIMIT 1
    ");
    $upd->bindValue(":ad", (int) $summary["ayat_dari"], PDO::PARAM_INT);
    $upd->bindValue(":as", (int) $summary["ayat_sampai"], PDO::PARAM_INT);
    $upd->bindValue(":st", $summary["status"], PDO::PARAM_STR);
    $upd->bindValue(":cat", $catatan, PDO::PARAM_STR);
    $upd->bindValue(":nocust", (string) $siswa["nocust"], PDO::PARAM_STR);
    $upd->bindValue(":nmcust", (string) $siswa["nmcust"], PDO::PARAM_STR);
    $upd->bindValue(":code01", (string) $siswa["code01"], PDO::PARAM_STR);
    $upd->bindValue(":kelas", (string) $siswa["kelas"], PDO::PARAM_STR);
    $upd->bindValue(":by", $by, PDO::PARAM_STR);
    $upd->bindValue(":id", $progressId, PDO::PARAM_INT);
    $upd->execute();

    if ($summary["status"] === "lunas") {
        if ($logId > 0) {
            $fix = $pdo->prepare("UPDATE aka_tahfid_progress_log SET status = 'lunas' WHERE id = :id LIMIT 1");
            $fix->bindValue(":id", $logId, PDO::PARAM_INT);
            $fix->execute();
        }
        tahfidMarkSetoranIfLunas($pdo, $siswa, $detailId, "lunas");
    } else {
        tahfidClearSetoranIfNotLunas($pdo, $custid, $detailId, $summary["status"]);
    }

    $nama = trim((string) ($row["surah_nama"] ?? "Surat"));
    $msg = $summary["status"] === "lunas"
        ? ($nama . " lunas / selesai")
        : ("Progress " . $nama . " tercatat (" . ($summary["progress_label"] ?: ("ayat " . $ayatDari . "–" . $ayatSampai)) . ")");
    return [
        "progress_id" => $progressId,
        "status" => $summary["status"],
        "message" => $msg,
    ];
}

function ensureTahfidTables(PDO $pdo): void
{
    static $ready = false;
    if ($ready) {
        return;
    }
    try {
        $pdo->query("SELECT id FROM aka_tahfid_jadwal LIMIT 0");
        $pdo->query("SELECT id FROM aka_tahfid_jadwal_detail LIMIT 0");
        $pdo->query("SELECT id FROM aka_tahfid_percepatan LIMIT 0");
        $pdo->query("SELECT id FROM aka_tahfid_setoran LIMIT 0");
        ensureTahfidJadwalCode03($pdo);
        ensureTahfidProgressTables($pdo);
        $ready = true;
        return;
    } catch (Throwable) {
        // Tabel belum lengkap.
    }
    try {
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS aka_tahfid_jadwal (
                id INT UNSIGNED NOT NULL AUTO_INCREMENT,
                code01 VARCHAR(20) NOT NULL,
                kelas VARCHAR(80) NOT NULL,
                code03 VARCHAR(20) NOT NULL DEFAULT '',
                created_by VARCHAR(50) NOT NULL DEFAULT '',
                updated_by VARCHAR(50) NOT NULL DEFAULT '',
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                UNIQUE KEY uk_unit_kelas (code01, kelas),
                KEY idx_code01 (code01),
                KEY idx_code03 (code03)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS aka_tahfid_jadwal_detail (
                id INT UNSIGNED NOT NULL AUTO_INCREMENT,
                jadwal_id INT UNSIGNED NOT NULL,
                urut INT NOT NULL DEFAULT 1,
                surah_nomor TINYINT UNSIGNED NOT NULL,
                surah_nama VARCHAR(80) NOT NULL DEFAULT '',
                juz_dari TINYINT UNSIGNED NOT NULL DEFAULT 1,
                juz_sampai TINYINT UNSIGNED NOT NULL DEFAULT 1,
                is_lengkap TINYINT(1) NOT NULL DEFAULT 1,
                ayat_dari SMALLINT UNSIGNED NULL DEFAULT NULL,
                ayat_sampai SMALLINT UNSIGNED NULL DEFAULT NULL,
                PRIMARY KEY (id),
                KEY idx_jadwal (jadwal_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS aka_tahfid_percepatan (
                id INT UNSIGNED NOT NULL AUTO_INCREMENT,
                custid VARCHAR(50) NOT NULL,
                nocust VARCHAR(50) NOT NULL,
                nmcust VARCHAR(150) NOT NULL DEFAULT '',
                code01 VARCHAR(20) NOT NULL DEFAULT '',
                kelas_asal VARCHAR(80) NOT NULL DEFAULT '',
                kelas_tujuan VARCHAR(80) NOT NULL,
                created_by VARCHAR(50) NOT NULL DEFAULT '',
                created_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                UNIQUE KEY uk_siswa_tujuan (custid, kelas_tujuan),
                KEY idx_custid (custid),
                KEY idx_code01 (code01)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS aka_tahfid_setoran (
                id INT UNSIGNED NOT NULL AUTO_INCREMENT,
                custid VARCHAR(50) NOT NULL,
                nocust VARCHAR(50) NOT NULL DEFAULT '',
                nmcust VARCHAR(150) NOT NULL DEFAULT '',
                code01 VARCHAR(20) NOT NULL DEFAULT '',
                kelas VARCHAR(80) NOT NULL DEFAULT '',
                jadwal_detail_id INT UNSIGNED NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'setor',
                created_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                UNIQUE KEY uk_siswa_detail (custid, jadwal_detail_id),
                KEY idx_custid (custid),
                KEY idx_detail (jadwal_detail_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");
        ensureTahfidJadwalCode03($pdo);
        ensureTahfidProgressTables($pdo);
        $ready = true;
    } catch (Throwable $e) {
        $msg = $e->getMessage();
        if (stripos($msg, "already exists") !== false) {
            ensureTahfidJadwalCode03($pdo);
            ensureTahfidProgressTables($pdo);
            $ready = true;
            return;
        }
        writeLog("TAHFID_CREATE_FAIL", ["message" => $msg]);
        fail(500, "Tabel tahfid belum ada. Jalankan ws/sql/aka_tahfid.sql");
    }
}

function tahfidResolveStaffCode01(array $auth, string $requested): string
{
    $own = staffUnitCode01($auth);
    $requested = trim($requested);
    if ($own !== "") {
        return $own;
    }
    return $requested;
}

function mapTahfidDetailRow(array $row): array
{
    $lengkap = ((int) ($row["is_lengkap"] ?? 1)) === 1;
    $dari = (int) ($row["ayat_dari"] ?? 1);
    $sampai = (int) ($row["ayat_sampai"] ?? $dari);
    $juzDari = (int) ($row["juz_dari"] ?? 1);
    $juzSampai = (int) ($row["juz_sampai"] ?? $juzDari);
    return [
        "id" => (int) ($row["id"] ?? 0),
        "jadwal_id" => (int) ($row["jadwal_id"] ?? 0),
        "urut" => (int) ($row["urut"] ?? 1),
        "surah_nomor" => (int) ($row["surah_nomor"] ?? 0),
        "surah_nama" => trim((string) ($row["surah_nama"] ?? "")),
        "juz_dari" => $juzDari,
        "juz_sampai" => $juzSampai,
        "juz_label" => tahfidJuzLabel($juzDari, $juzSampai),
        "is_lengkap" => $lengkap,
        "ayat_dari" => $dari,
        "ayat_sampai" => $sampai,
        "ayat_label" => tahfidAyatLabel($lengkap, $dari, $sampai),
        "kelas_sumber" => trim((string) ($row["kelas_sumber"] ?? "")),
        "sumber" => trim((string) ($row["sumber"] ?? "")),
        "sudah_setor" => ((int) ($row["sudah_setor"] ?? 0)) === 1,
        "setor_at" => trim((string) ($row["setor_at"] ?? "")),
        "progress_status" => trim((string) ($row["progress_status"] ?? "")),
        "progress_status_label" => tahfidProgressStatusLabel(trim((string) ($row["progress_status"] ?? ""))),
        "progress_ayat_dari" => (int) ($row["progress_ayat_dari"] ?? 0),
        "progress_ayat_sampai" => (int) ($row["progress_ayat_sampai"] ?? 0),
        "progress_label" => trim((string) ($row["progress_label"] ?? "")),
        "progress_catatan" => trim((string) ($row["progress_catatan"] ?? "")),
        "progress_at" => trim((string) ($row["progress_at"] ?? "")),
        "logs" => is_array($row["logs"] ?? null) ? $row["logs"] : [],
    ];
}

function tahfidFetchDetails(PDO $pdo, int $jadwalId): array
{
    $stmt = $pdo->prepare("
        SELECT id, jadwal_id, urut, surah_nomor, surah_nama, juz_dari, juz_sampai, is_lengkap, ayat_dari, ayat_sampai
        FROM aka_tahfid_jadwal_detail
        WHERE jadwal_id = :id
        ORDER BY urut ASC, id ASC
    ");
    $stmt->bindValue(":id", $jadwalId, PDO::PARAM_INT);
    $stmt->execute();
    $items = [];
    foreach ($stmt->fetchAll() ?: [] as $row) {
        if (is_array($row)) {
            $items[] = mapTahfidDetailRow($row);
        }
    }
    return $items;
}

function tahfidFetchJadwal(PDO $pdo, int $id, string $userCode01): ?array
{
    $sql = "
        SELECT j.id, j.code01, j.kelas, j.code03, j.created_by, j.updated_by, j.created_at, j.updated_at,
               TRIM(ms.DESC01) AS sekolah
        FROM aka_tahfid_jadwal j
        LEFT JOIN mst_sekolah ms ON ms.CODE01 = j.code01
        WHERE j.id = :id
          AND (:code01_empty = '' OR j.code01 = :code01_value)
        LIMIT 1
    ";
    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(":id", $id, PDO::PARAM_INT);
    $stmt->bindValue(":code01_empty", $userCode01, PDO::PARAM_STR);
    $stmt->bindValue(":code01_value", $userCode01, PDO::PARAM_STR);
    $stmt->execute();
    $row = $stmt->fetch();
    if (!$row) {
        return null;
    }
    $item = [
        "id" => (int) $row["id"],
        "code01" => trim((string) $row["code01"]),
        "sekolah" => trim((string) ($row["sekolah"] ?? "")),
        "kelas" => trim((string) $row["kelas"]),
        "code03" => trim((string) ($row["code03"] ?? "")),
        "created_by" => trim((string) ($row["created_by"] ?? "")),
        "updated_by" => trim((string) ($row["updated_by"] ?? "")),
        "created_at" => trim((string) ($row["created_at"] ?? "")),
        "updated_at" => trim((string) ($row["updated_at"] ?? "")),
    ];
    $item["details"] = tahfidFetchDetails($pdo, $item["id"]);
    return $item;
}

function tahfidParseDetails(array $req): array
{
    $raw = $req["details"] ?? [];
    if (is_string($raw)) {
        $decoded = json_decode($raw, true);
        $raw = is_array($decoded) ? $decoded : [];
    }
    if (!is_array($raw) || count($raw) === 0) {
        fail(422, "Jadwal harus berisi minimal satu surat");
    }
    $items = [];
    $urut = 0;
    foreach ($raw as $row) {
        if (!is_array($row)) {
            continue;
        }
        $nomor = (int) ($row["surah_nomor"] ?? 0);
        $maxAyat = quranSurahAyatCount($nomor);
        if ($maxAyat < 1) {
            fail(422, "Nomor surat tidak valid");
        }
        $nama = trim((string) ($row["surah_nama"] ?? ""));
        if ($nama === "") {
            $nama = "Surat " . $nomor;
        }
        $nama = mb_substr($nama, 0, 80);
        $lengkap = !empty($row["is_lengkap"]);
        $dari = $lengkap ? 1 : (int) ($row["ayat_dari"] ?? 0);
        $sampai = $lengkap ? $maxAyat : (int) ($row["ayat_sampai"] ?? 0);
        if ($dari < 1 || $sampai < $dari || $sampai > $maxAyat) {
            fail(422, "Rentang ayat " . $nama . " tidak valid (1–" . $maxAyat . ")");
        }
        $urut++;
        $items[] = [
            "urut" => $urut,
            "surah_nomor" => $nomor,
            "surah_nama" => $nama,
            "is_lengkap" => $lengkap ? 1 : 0,
            "ayat_dari" => $dari,
            "ayat_sampai" => $sampai,
            "juz_dari" => quranJuzForAyah($nomor, $dari),
            "juz_sampai" => quranJuzForAyah($nomor, $sampai),
        ];
    }
    if (count($items) === 0) {
        fail(422, "Jadwal harus berisi minimal satu surat");
    }
    return $items;
}

function tahfidMstKelasHasCode03(PDO $pdo): bool
{
    static $has = null;
    if ($has !== null) {
        return $has;
    }
    try {
        $pdo->query("SELECT code03 FROM mst_kelas LIMIT 0");
        $has = true;
    } catch (Throwable) {
        $has = false;
    }
    return $has;
}

function tahfidMapMstKelasRow(array $row): array
{
    $id = (int) ($row["id"] ?? 0);
    $jenjang = trim((string) ($row["jenjang"] ?? ""));
    $rombel = trim((string) ($row["kelas"] ?? ""));
    $nama = $jenjang !== "" ? $jenjang : $rombel;
    $code03 = trim((string) ($row["code03"] ?? ""));
    if ($code03 === "" && $id > 0) {
        $code03 = (string) $id;
    }
    return [
        "id" => $id,
        "code03" => $code03,
        "kelas" => $nama,
        "rombel" => $rombel,
    ];
}

function tahfidSekolahUnitAliases(PDO $pdo, string $code01): array
{
    $aliases = [strtoupper(trim($code01))];
    $stmt = $pdo->prepare("SELECT TRIM(CODE01) AS code01, TRIM(DESC01) AS sekolah FROM mst_sekolah WHERE CODE01 = :c LIMIT 1");
    $stmt->bindValue(":c", $code01, PDO::PARAM_STR);
    $stmt->execute();
    $row = $stmt->fetch();
    if (is_array($row)) {
        $name = trim((string) ($row["sekolah"] ?? ""));
        if ($name !== "") {
            $aliases[] = strtoupper($name);
            if (preg_match('/^[A-Za-z]+/', $name, $m)) {
                $aliases[] = strtoupper($m[0]);
            }
        }
    }
    return array_values(array_unique(array_filter($aliases, static fn ($v) => $v !== "")));
}

function tahfidListKelas(PDO $pdo, string $code01): array
{
    $code01 = trim($code01);
    if ($code01 === "") {
        return [];
    }
    $aliases = tahfidSekolahUnitAliases($pdo, $code01);
    if (count($aliases) === 0) {
        return [];
    }
    $placeholders = [];
    $bind = [];
    foreach ($aliases as $i => $alias) {
        $key = ":u" . $i;
        $placeholders[] = $key;
        $bind[$key] = $alias;
    }
    $code03Col = tahfidMstKelasHasCode03($pdo) ? ", TRIM(k.code03) AS code03" : "";
    $sql = "
        SELECT k.id, TRIM(k.kelas) AS kelas, TRIM(k.jenjang) AS jenjang, TRIM(k.unit) AS unit
               {$code03Col}
        FROM mst_kelas k
        WHERE UPPER(TRIM(k.unit)) IN (" . implode(", ", $placeholders) . ")
          AND (TRIM(IFNULL(k.jenjang, '')) <> '' OR TRIM(IFNULL(k.kelas, '')) <> '')
        ORDER BY k.jenjang ASC, k.kelas ASC, k.id ASC
    ";
    try {
        $stmt = $pdo->prepare($sql);
        foreach ($bind as $key => $val) {
            $stmt->bindValue($key, $val, PDO::PARAM_STR);
        }
        $stmt->execute();
    } catch (Throwable $e) {
        writeLog("TAHFID_MST_KELAS_FAIL", ["message" => $e->getMessage(), "code01" => $code01]);
        fail(500, "Tabel mst_kelas belum bisa dibaca. Periksa kolom id, kelas, jenjang, unit.");
    }
    $items = [];
    $seen = [];
    foreach ($stmt->fetchAll() ?: [] as $row) {
        if (!is_array($row)) {
            continue;
        }
        $mapped = tahfidMapMstKelasRow($row);
        if ($mapped["id"] < 1 || $mapped["kelas"] === "") {
            continue;
        }
        $key = $mapped["code03"] !== "" ? $mapped["code03"] : (string) $mapped["id"];
        if (isset($seen[$key])) {
            continue;
        }
        $seen[$key] = true;
        $items[] = $mapped;
    }
    return $items;
}

function tahfidResolveSelectedKelas(PDO $pdo, string $code01, array $req): array
{
    $raw = $req["kelas_id"] ?? $req["kelas"] ?? [];
    if (is_string($raw)) {
        $decoded = json_decode($raw, true);
        $raw = is_array($decoded) ? $decoded : preg_split('/\s*,\s*/', $raw);
    }
    if (!is_array($raw)) {
        $raw = [];
    }
    $ids = [];
    $names = [];
    foreach ($raw as $row) {
        if (is_array($row)) {
            $id = (int) ($row["id"] ?? $row["code03"] ?? 0);
            $name = trim((string) ($row["kelas"] ?? $row["nama"] ?? ""));
        } else {
            $text = trim((string) $row);
            $id = ctype_digit($text) ? (int) $text : 0;
            $name = $id > 0 ? "" : $text;
        }
        if ($id > 0) {
            $ids[$id] = $id;
        } elseif ($name !== "") {
            $names[mb_strtoupper($name)] = $name;
        }
    }
    $all = tahfidListKelas($pdo, $code01);
    $byId = [];
    $byName = [];
    foreach ($all as $row) {
        $byId[(int) $row["id"]] = $row;
        $code03 = (int) ($row["code03"] ?? 0);
        if ($code03 > 0) {
            $byId[$code03] = $row;
        }
        $byName[mb_strtoupper((string) $row["kelas"])] = $row;
    }
    $selected = [];
    $seen = [];
    foreach ($ids as $id) {
        if (!isset($byId[$id])) {
            fail(422, "Kelas tidak valid untuk unit ini");
        }
        $key = (string) $byId[$id]["id"];
        if (isset($seen[$key])) {
            continue;
        }
        $seen[$key] = true;
        $selected[] = $byId[$id];
    }
    foreach ($names as $upper => $_name) {
        if (!isset($byName[$upper])) {
            fail(422, "Kelas tidak ditemukan di master kelas unit ini");
        }
        $key = (string) $byName[$upper]["id"];
        if (isset($seen[$key])) {
            continue;
        }
        $seen[$key] = true;
        $selected[] = $byName[$upper];
    }
    if (count($selected) === 0) {
        fail(422, "Pilih minimal satu kelas dari master kelas");
    }
    return $selected;
}

function tahfidUpsertJadwal(PDO $pdo, string $code01, string $kelas, string $code03, array $details, string $by): int
{
    $existingId = 0;
    if ($code03 !== "") {
        $find = $pdo->prepare("SELECT id FROM aka_tahfid_jadwal WHERE code01 = :c AND code03 = :k LIMIT 1");
        $find->bindValue(":c", $code01, PDO::PARAM_STR);
        $find->bindValue(":k", $code03, PDO::PARAM_STR);
        $find->execute();
        $existingId = (int) ($find->fetchColumn() ?: 0);
    }
    if ($existingId < 1) {
        $find = $pdo->prepare("SELECT id FROM aka_tahfid_jadwal WHERE code01 = :c AND kelas = :k LIMIT 1");
        $find->bindValue(":c", $code01, PDO::PARAM_STR);
        $find->bindValue(":k", $kelas, PDO::PARAM_STR);
        $find->execute();
        $existingId = (int) ($find->fetchColumn() ?: 0);
    }
    if ($existingId > 0) {
        $upd = $pdo->prepare("
            UPDATE aka_tahfid_jadwal
            SET kelas = :kelas, code03 = :code03, updated_by = :by, updated_at = NOW()
            WHERE id = :id LIMIT 1
        ");
        $upd->bindValue(":kelas", $kelas, PDO::PARAM_STR);
        $upd->bindValue(":code03", $code03, PDO::PARAM_STR);
        $upd->bindValue(":by", $by, PDO::PARAM_STR);
        $upd->bindValue(":id", $existingId, PDO::PARAM_INT);
        $upd->execute();
        tahfidReplaceDetails($pdo, $existingId, $details);
        return $existingId;
    }

    $ins = $pdo->prepare("
        INSERT INTO aka_tahfid_jadwal (code01, kelas, code03, created_by, updated_by, created_at, updated_at)
        VALUES (:code01, :kelas, :code03, :by1, :by2, NOW(), NOW())
    ");
    $ins->bindValue(":code01", $code01, PDO::PARAM_STR);
    $ins->bindValue(":kelas", $kelas, PDO::PARAM_STR);
    $ins->bindValue(":code03", $code03, PDO::PARAM_STR);
    $ins->bindValue(":by1", $by, PDO::PARAM_STR);
    $ins->bindValue(":by2", $by, PDO::PARAM_STR);
    $ins->execute();
    $newId = (int) $pdo->lastInsertId();
    tahfidReplaceDetails($pdo, $newId, $details);
    return $newId;
}

function tahfidFetchSiswaLive(PDO $pdo, string $custid): ?array
{
    $stmt = $pdo->prepare("
        SELECT
            TRIM(c.CUSTID) AS custid,
            TRIM(c.NOCUST) AS nocust,
            TRIM(c.NMCUST) AS nmcust,
            TRIM(c.DESC02) AS kelas,
            TRIM(c.CODE01) AS code01,
            TRIM(ms.DESC01) AS sekolah
        FROM scctcust c
        LEFT JOIN mst_sekolah ms ON ms.CODE01 = c.CODE01
        WHERE TRIM(c.CUSTID) = :custid
        LIMIT 1
    ");
    $stmt->bindValue(":custid", $custid, PDO::PARAM_STR);
    $stmt->execute();
    $row = $stmt->fetch();
    return $row ?: null;
}

function tahfidReplaceDetails(PDO $pdo, int $jadwalId, array $details): void
{
    $old = $pdo->prepare("SELECT id FROM aka_tahfid_jadwal_detail WHERE jadwal_id = :id");
    $old->bindValue(":id", $jadwalId, PDO::PARAM_INT);
    $old->execute();
    $ids = [];
    foreach ($old->fetchAll() ?: [] as $row) {
        $ids[] = (int) ($row["id"] ?? 0);
    }
    if (count($ids) > 0) {
        $in = implode(",", array_fill(0, count($ids), "?"));
        $delSetor = $pdo->prepare("DELETE FROM aka_tahfid_setoran WHERE jadwal_detail_id IN ($in)");
        $delSetor->execute($ids);
    }
    $del = $pdo->prepare("DELETE FROM aka_tahfid_jadwal_detail WHERE jadwal_id = :id");
    $del->bindValue(":id", $jadwalId, PDO::PARAM_INT);
    $del->execute();

    $ins = $pdo->prepare("
        INSERT INTO aka_tahfid_jadwal_detail
            (jadwal_id, urut, surah_nomor, surah_nama, juz_dari, juz_sampai, is_lengkap, ayat_dari, ayat_sampai)
        VALUES
            (:jadwal_id, :urut, :surah_nomor, :surah_nama, :juz_dari, :juz_sampai, :is_lengkap, :ayat_dari, :ayat_sampai)
    ");
    foreach ($details as $row) {
        $ins->bindValue(":jadwal_id", $jadwalId, PDO::PARAM_INT);
        $ins->bindValue(":urut", (int) $row["urut"], PDO::PARAM_INT);
        $ins->bindValue(":surah_nomor", (int) $row["surah_nomor"], PDO::PARAM_INT);
        $ins->bindValue(":surah_nama", (string) $row["surah_nama"], PDO::PARAM_STR);
        $ins->bindValue(":juz_dari", (int) $row["juz_dari"], PDO::PARAM_INT);
        $ins->bindValue(":juz_sampai", (int) $row["juz_sampai"], PDO::PARAM_INT);
        $ins->bindValue(":is_lengkap", (int) $row["is_lengkap"], PDO::PARAM_INT);
        $ins->bindValue(":ayat_dari", (int) $row["ayat_dari"], PDO::PARAM_INT);
        $ins->bindValue(":ayat_sampai", (int) $row["ayat_sampai"], PDO::PARAM_INT);
        $ins->execute();
    }
}

function doManageTahfid(array $req, array $auth): array
{
    $action = strtolower(trim((string) ($req["action"] ?? "list")));
    $pdo = dbConnectPdo();
    ensureTahfidTables($pdo);

    $siswaActions = ["myjadwal", "submitsetoran"];
    if (in_array($action, $siswaActions, true)) {
        if (!tahfidIsSiswaAuth($auth)) {
            fail(403, "Aksi ini hanya untuk siswa");
        }
        if ($action === "myjadwal") {
            return tahfidMyJadwal($pdo, $auth);
        }
        return tahfidSubmitSetoran($pdo, $req, $auth);
    }

    assertApprovalRole($auth);
    $userCode01 = staffUnitCode01($auth);
    $by = approvalStaffUsername($auth);

    if ($action === "list" || $action === "listjadwal") {
        $filterCode = tahfidResolveStaffCode01($auth, (string) ($req["code01"] ?? ""));
        $sql = "
            SELECT j.id, j.code01, j.kelas, j.code03, j.created_by, j.updated_at,
                   TRIM(ms.DESC01) AS sekolah,
                   (SELECT COUNT(*) FROM aka_tahfid_jadwal_detail d WHERE d.jadwal_id = j.id) AS jumlah_surat
            FROM aka_tahfid_jadwal j
            LEFT JOIN mst_sekolah ms ON ms.CODE01 = j.code01
            WHERE (:code01_empty = '' OR j.code01 = :code01_value)
            ORDER BY ms.DESC01 ASC, j.kelas ASC
        ";
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(":code01_empty", $filterCode, PDO::PARAM_STR);
        $stmt->bindValue(":code01_value", $filterCode, PDO::PARAM_STR);
        $stmt->execute();
        $items = [];
        foreach ($stmt->fetchAll() ?: [] as $row) {
            if (!is_array($row)) {
                continue;
            }
            $items[] = [
                "id" => (int) $row["id"],
                "code01" => trim((string) $row["code01"]),
                "sekolah" => trim((string) ($row["sekolah"] ?? "")),
                "kelas" => trim((string) $row["kelas"]),
                "code03" => trim((string) ($row["code03"] ?? "")),
                "jumlah_surat" => (int) ($row["jumlah_surat"] ?? 0),
                "updated_at" => trim((string) ($row["updated_at"] ?? "")),
                "created_by" => trim((string) ($row["created_by"] ?? "")),
                "details" => tahfidFetchDetails($pdo, (int) $row["id"]),
            ];
        }
        return [
            "items" => $items,
            "sekolah" => fetchSekolahMap($pdo),
            "kelas" => $filterCode !== "" ? tahfidListKelas($pdo, $filterCode) : [],
            "scope_sekolah" => $userCode01 !== "" ? fetchScopeSekolahName($pdo, $userCode01) : "",
        ];
    }

    if ($action === "listkelas") {
        $code01 = tahfidResolveStaffCode01($auth, (string) ($req["code01"] ?? ""));
        if ($code01 === "") {
            fail(422, "Pilih unit terlebih dahulu");
        }
        return ["kelas" => tahfidListKelas($pdo, $code01), "code01" => $code01];
    }

    if ($action === "get") {
        $id = (int) ($req["id"] ?? 0);
        if ($id < 1) {
            fail(422, "ID jadwal tidak valid");
        }
        $item = tahfidFetchJadwal($pdo, $id, $userCode01);
        if ($item === null) {
            fail(404, "Jadwal tidak ditemukan");
        }
        return [
            "item" => $item,
            "sekolah" => fetchSekolahMap($pdo),
            "kelas" => tahfidListKelas($pdo, $item["code01"]),
            "scope_sekolah" => $userCode01 !== "" ? fetchScopeSekolahName($pdo, $userCode01) : "",
        ];
    }

    if ($action === "save" || $action === "create" || $action === "update") {
        $code01 = tahfidResolveStaffCode01($auth, (string) ($req["code01"] ?? ""));
        if ($code01 === "" || !sekolahCodeExists($pdo, $code01)) {
            fail(422, "Unit tidak valid");
        }
        $selectedKelas = tahfidResolveSelectedKelas($pdo, $code01, $req);
        $details = tahfidParseDetails($req);
        $ids = [];
        $kelasNames = [];
        foreach ($selectedKelas as $kelasRow) {
            $kelas = trim((string) ($kelasRow["kelas"] ?? ""));
            $code03 = trim((string) ($kelasRow["code03"] ?? ""));
            if ($code03 === "" && (int) ($kelasRow["id"] ?? 0) > 0) {
                $code03 = (string) $kelasRow["id"];
            }
            $ids[] = tahfidUpsertJadwal($pdo, $code01, $kelas, $code03, $details, $by);
            $kelasNames[] = $kelas;
        }
        writeLog("TAHFID_JADWAL_SAVE", ["code01" => $code01, "kelas" => $kelasNames, "code03" => array_column($selectedKelas, "code03"), "by" => $by]);
        $jumlah = count($selectedKelas);
        return [
            "id" => $ids[0] ?? 0,
            "ids" => $ids,
            "message" => $jumlah === 1
                ? "Jadwal berhasil disimpan"
                : "Jadwal berhasil disimpan untuk " . $jumlah . " kelas",
        ];
    }

    if ($action === "delete") {
        $id = (int) ($req["id"] ?? 0);
        if ($id < 1) {
            fail(422, "ID jadwal tidak valid");
        }
        $item = tahfidFetchJadwal($pdo, $id, $userCode01);
        if ($item === null) {
            fail(404, "Jadwal tidak ditemukan");
        }
        tahfidReplaceDetails($pdo, $id, []);
        $del = $pdo->prepare("DELETE FROM aka_tahfid_jadwal WHERE id = :id LIMIT 1");
        $del->bindValue(":id", $id, PDO::PARAM_INT);
        $del->execute();
        writeLog("TAHFID_JADWAL_DELETE", ["id" => $id, "by" => $by]);
        return ["message" => "Jadwal dihapus"];
    }

    if ($action === "listpercepatan") {
        $filterCode = tahfidResolveStaffCode01($auth, (string) ($req["code01"] ?? ""));
        $sql = "
            SELECT p.id, p.custid, p.nocust, p.nmcust, p.code01, p.kelas_asal, p.kelas_tujuan, p.created_by, p.created_at,
                   TRIM(ms.DESC01) AS sekolah
            FROM aka_tahfid_percepatan p
            LEFT JOIN mst_sekolah ms ON ms.CODE01 = p.code01
            WHERE (:code01_empty = '' OR p.code01 = :code01_value)
            ORDER BY p.created_at DESC
        ";
        $stmt = $pdo->prepare($sql);
        $stmt->bindValue(":code01_empty", $filterCode, PDO::PARAM_STR);
        $stmt->bindValue(":code01_value", $filterCode, PDO::PARAM_STR);
        $stmt->execute();
        $items = [];
        foreach ($stmt->fetchAll() ?: [] as $row) {
            if (!is_array($row)) {
                continue;
            }
            $items[] = [
                "id" => (int) $row["id"],
                "custid" => trim((string) $row["custid"]),
                "nocust" => trim((string) $row["nocust"]),
                "nmcust" => trim((string) $row["nmcust"]),
                "code01" => trim((string) $row["code01"]),
                "sekolah" => trim((string) ($row["sekolah"] ?? "")),
                "kelas_asal" => trim((string) $row["kelas_asal"]),
                "kelas_tujuan" => trim((string) $row["kelas_tujuan"]),
                "created_by" => trim((string) ($row["created_by"] ?? "")),
                "created_at" => trim((string) ($row["created_at"] ?? "")),
            ];
        }
        $jadwalKelas = [];
        if ($filterCode !== "") {
            $jk = $pdo->prepare("SELECT TRIM(kelas) AS kelas FROM aka_tahfid_jadwal WHERE code01 = :c ORDER BY kelas ASC");
            $jk->bindValue(":c", $filterCode, PDO::PARAM_STR);
            $jk->execute();
            foreach ($jk->fetchAll() ?: [] as $row) {
                $k = trim((string) ($row["kelas"] ?? ""));
                if ($k !== "") {
                    $jadwalKelas[] = $k;
                }
            }
        }
        return [
            "items" => $items,
            "sekolah" => fetchSekolahMap($pdo),
            "jadwal_kelas" => $jadwalKelas,
            "scope_sekolah" => $userCode01 !== "" ? fetchScopeSekolahName($pdo, $userCode01) : "",
        ];
    }

    if ($action === "savepercepatan") {
        $nocust = trim((string) ($req["nis"] ?? $req["nocust"] ?? ""));
        $kelasTujuan = trim((string) ($req["kelas_tujuan"] ?? ""));
        if ($nocust === "" || !secure_validate_nocust($nocust)) {
            fail(422, "NIS siswa tidak valid");
        }
        if ($kelasTujuan === "") {
            fail(422, "Kelas tujuan wajib diisi");
        }
        $siswa = fetchSiswaByNocust($pdo, $nocust, $userCode01);
        if (!$siswa) {
            fail(422, "Siswa tidak ditemukan pada unit Anda");
        }
        $code01 = trim((string) $siswa["code01"]);
        $kelasAsal = trim((string) $siswa["kelas"]);
        if ($kelasTujuan === $kelasAsal) {
            fail(422, "Kelas tujuan harus berbeda dari kelas siswa");
        }
        $hasJadwal = $pdo->prepare("SELECT id FROM aka_tahfid_jadwal WHERE code01 = :c AND kelas = :k LIMIT 1");
        $hasJadwal->bindValue(":c", $code01, PDO::PARAM_STR);
        $hasJadwal->bindValue(":k", $kelasTujuan, PDO::PARAM_STR);
        $hasJadwal->execute();
        if (!(int) ($hasJadwal->fetchColumn() ?: 0)) {
            fail(422, "Kelas tujuan belum memiliki jadwal tahfid");
        }
        try {
            $ins = $pdo->prepare("
                INSERT INTO aka_tahfid_percepatan
                    (custid, nocust, nmcust, code01, kelas_asal, kelas_tujuan, created_by, created_at)
                VALUES
                    (:custid, :nocust, :nmcust, :code01, :asal, :tujuan, :by, NOW())
            ");
            $ins->bindValue(":custid", (string) $siswa["custid"], PDO::PARAM_STR);
            $ins->bindValue(":nocust", (string) $siswa["nocust"], PDO::PARAM_STR);
            $ins->bindValue(":nmcust", (string) $siswa["nmcust"], PDO::PARAM_STR);
            $ins->bindValue(":code01", $code01, PDO::PARAM_STR);
            $ins->bindValue(":asal", $kelasAsal, PDO::PARAM_STR);
            $ins->bindValue(":tujuan", $kelasTujuan, PDO::PARAM_STR);
            $ins->bindValue(":by", $by, PDO::PARAM_STR);
            $ins->execute();
        } catch (Throwable $e) {
            if (stripos($e->getMessage(), "Duplicate") !== false) {
                fail(422, "Siswa ini sudah ditugaskan ke kelas tersebut");
            }
            throw $e;
        }
        writeLog("TAHFID_PERCEPATAN_CREATE", ["nocust" => $siswa["nocust"], "tujuan" => $kelasTujuan, "by" => $by]);
        return ["message" => "Percepatan berhasil disimpan"];
    }

    if ($action === "deletepercepatan") {
        $id = (int) ($req["id"] ?? 0);
        if ($id < 1) {
            fail(422, "ID percepatan tidak valid");
        }
        $sql = "
            DELETE FROM aka_tahfid_percepatan
            WHERE id = :id AND (:code01_empty = '' OR code01 = :code01_value)
            LIMIT 1
        ";
        $del = $pdo->prepare($sql);
        $del->bindValue(":id", $id, PDO::PARAM_INT);
        $del->bindValue(":code01_empty", $userCode01, PDO::PARAM_STR);
        $del->bindValue(":code01_value", $userCode01, PDO::PARAM_STR);
        $del->execute();
        if ($del->rowCount() < 1) {
            fail(404, "Data percepatan tidak ditemukan");
        }
        writeLog("TAHFID_PERCEPATAN_DELETE", ["id" => $id, "by" => $by]);
        return ["message" => "Percepatan dihapus"];
    }

    if ($action === "siswaprogress" || $action === "getprogress") {
        return tahfidStaffSiswaProgress($pdo, $req, $auth);
    }

    if ($action === "saveprogress") {
        return tahfidStaffSaveProgress($pdo, $req, $auth);
    }

    fail(422, "Aksi tahfid tidak valid");
}

function tahfidSiswaJadwalGroups(PDO $pdo, array $siswa, bool $withLogs = false): array
{
    $custid = trim((string) $siswa["custid"]);
    $code01 = trim((string) $siswa["code01"]);
    $kelas = trim((string) $siswa["kelas"]);
    $groups = [];

    $pushGroup = static function (string $sumber, string $kelasSumber, ?array $jadwal) use (&$groups, $pdo, $custid, $withLogs): void {
        if ($jadwal === null) {
            return;
        }
        $jid = (int) $jadwal["id"];
        $stmt = $pdo->prepare("
            SELECT d.id, d.jadwal_id, d.urut, d.surah_nomor, d.surah_nama, d.juz_dari, d.juz_sampai,
                   d.is_lengkap, d.ayat_dari, d.ayat_sampai,
                   CASE WHEN s.id IS NULL THEN 0 ELSE 1 END AS sudah_setor,
                   s.created_at AS setor_at,
                   TRIM(p.status) AS progress_status,
                   p.ayat_dari AS progress_ayat_dari,
                   p.ayat_sampai AS progress_ayat_sampai,
                   p.catatan AS progress_catatan,
                   p.updated_at AS progress_at
            FROM aka_tahfid_jadwal_detail d
            LEFT JOIN aka_tahfid_setoran s ON s.jadwal_detail_id = d.id AND s.custid = :custid
            LEFT JOIN aka_tahfid_progress p ON p.jadwal_detail_id = d.id AND p.custid = :custid2
            WHERE d.jadwal_id = :jid
            ORDER BY d.urut ASC, d.id ASC
        ");
        $stmt->bindValue(":custid", $custid, PDO::PARAM_STR);
        $stmt->bindValue(":custid2", $custid, PDO::PARAM_STR);
        $stmt->bindValue(":jid", $jid, PDO::PARAM_INT);
        $stmt->execute();
        $details = [];
        $lunas = 0;
        $proses = 0;
        foreach ($stmt->fetchAll() ?: [] as $row) {
            if (!is_array($row)) {
                continue;
            }
            $row["kelas_sumber"] = $kelasSumber;
            $row["sumber"] = $sumber;
            $status = trim((string) ($row["progress_status"] ?? ""));
            if ($status === "" && ((int) ($row["sudah_setor"] ?? 0)) === 1) {
                $status = "lunas";
                $row["progress_status"] = "lunas";
            }
            if ($status === "lunas") {
                $lunas++;
                $row["progress_label"] = tahfidAyatLabel(true, (int) $row["ayat_dari"], (int) $row["ayat_sampai"]);
            } elseif ($status === "proses") {
                $proses++;
                $pd = (int) ($row["progress_ayat_dari"] ?? 0);
                $ps = (int) ($row["progress_ayat_sampai"] ?? 0);
                $row["progress_label"] = ($pd > 0 && $ps > 0) ? ("Ayat " . $pd . "–" . $ps) : "Proses";
            } else {
                $row["progress_status"] = "belum";
                $row["progress_label"] = "";
            }
            $mapped = mapTahfidDetailRow($row);
            if ($withLogs) {
                $mapped["logs"] = tahfidFetchProgressLogs($pdo, $custid, (int) $mapped["id"]);
            }
            $details[] = $mapped;
        }
        $groups[] = [
            "sumber" => $sumber,
            "kelas" => $kelasSumber,
            "jadwal_id" => $jid,
            "jumlah_surat" => count($details),
            "jumlah_lunas" => $lunas,
            "jumlah_proses" => $proses,
            "details" => $details,
        ];
    };

    $findJadwal = $pdo->prepare("
        SELECT j.id, j.code01, j.kelas, TRIM(ms.DESC01) AS sekolah
        FROM aka_tahfid_jadwal j
        LEFT JOIN mst_sekolah ms ON ms.CODE01 = j.code01
        WHERE j.code01 = :c AND j.kelas = :k
        LIMIT 1
    ");
    $findJadwal->bindValue(":c", $code01, PDO::PARAM_STR);
    $findJadwal->bindValue(":k", $kelas, PDO::PARAM_STR);
    $findJadwal->execute();
    $own = $findJadwal->fetch() ?: null;
    $pushGroup("kelas", $kelas, is_array($own) ? $own : null);

    $acc = $pdo->prepare("SELECT kelas_tujuan FROM aka_tahfid_percepatan WHERE custid = :c ORDER BY id ASC");
    $acc->bindValue(":c", $custid, PDO::PARAM_STR);
    $acc->execute();
    foreach ($acc->fetchAll() ?: [] as $row) {
        $tujuan = trim((string) ($row["kelas_tujuan"] ?? ""));
        if ($tujuan === "" || $tujuan === $kelas) {
            continue;
        }
        $findJadwal->bindValue(":c", $code01, PDO::PARAM_STR);
        $findJadwal->bindValue(":k", $tujuan, PDO::PARAM_STR);
        $findJadwal->execute();
        $extra = $findJadwal->fetch() ?: null;
        $pushGroup("percepatan", $tujuan, is_array($extra) ? $extra : null);
    }

    return $groups;
}

function tahfidMyJadwal(PDO $pdo, array $auth): array
{
    $custid = trim((string) ($auth["custid"] ?? ""));
    $siswa = tahfidFetchSiswaLive($pdo, $custid);
    if (!$siswa) {
        fail(404, "Data siswa tidak ditemukan");
    }
    return [
        "siswa" => [
            "custid" => trim((string) $siswa["custid"]),
            "nocust" => trim((string) $siswa["nocust"]),
            "nmcust" => trim((string) $siswa["nmcust"]),
            "kelas" => trim((string) $siswa["kelas"]),
            "code01" => trim((string) $siswa["code01"]),
            "sekolah" => trim((string) ($siswa["sekolah"] ?? "")),
        ],
        "groups" => tahfidSiswaJadwalGroups($pdo, $siswa, false),
    ];
}

function tahfidStaffSiswaProgress(PDO $pdo, array $req, array $auth): array
{
    $userCode01 = staffUnitCode01($auth);
    $nocust = trim((string) ($req["nis"] ?? $req["nocust"] ?? ""));
    if ($nocust === "" || !secure_validate_nocust($nocust)) {
        fail(422, "NIS siswi tidak valid");
    }
    $siswa = fetchSiswaByNocust($pdo, $nocust, $userCode01);
    if (!$siswa) {
        fail(404, "Siswi tidak ditemukan pada unit Anda");
    }
    $groups = tahfidSiswaJadwalGroups($pdo, $siswa, true);
    $lunas = 0;
    $total = 0;
    foreach ($groups as $g) {
        $total += (int) ($g["jumlah_surat"] ?? 0);
        $lunas += (int) ($g["jumlah_lunas"] ?? 0);
    }
    return [
        "siswa" => [
            "custid" => trim((string) $siswa["custid"]),
            "nocust" => trim((string) $siswa["nocust"]),
            "nmcust" => trim((string) $siswa["nmcust"]),
            "kelas" => trim((string) $siswa["kelas"]),
            "code01" => trim((string) $siswa["code01"]),
            "sekolah" => trim((string) ($siswa["sekolah"] ?? "")),
        ],
        "groups" => $groups,
        "ringkasan" => [
            "jumlah_surat" => $total,
            "jumlah_lunas" => $lunas,
        ],
    ];
}

function tahfidStaffSaveProgress(PDO $pdo, array $req, array $auth): array
{
    $userCode01 = staffUnitCode01($auth);
    $by = approvalStaffUsername($auth);
    $nocust = trim((string) ($req["nis"] ?? $req["nocust"] ?? ""));
    $detailId = (int) ($req["jadwal_detail_id"] ?? 0);
    if ($nocust === "" || !secure_validate_nocust($nocust)) {
        fail(422, "NIS siswi tidak valid");
    }
    if ($detailId < 1) {
        fail(422, "Item jadwal tidak valid");
    }
    $siswa = fetchSiswaByNocust($pdo, $nocust, $userCode01);
    if (!$siswa) {
        fail(404, "Siswi tidak ditemukan pada unit Anda");
    }
    $forceLunas = in_array(strtolower(trim((string) ($req["status"] ?? $req["mode"] ?? ""))), ["lunas", "selesai", "lengkap"], true)
        || ((int) ($req["is_lengkap"] ?? 0)) === 1;
    $ayatDari = (int) ($req["ayat_dari"] ?? 0);
    $ayatSampai = (int) ($req["ayat_sampai"] ?? 0);
    $catatan = (string) ($req["catatan"] ?? "");
    $result = tahfidUpsertProgress($pdo, $siswa, $detailId, $ayatDari, $ayatSampai, $forceLunas, $catatan, $by);
    writeLog("TAHFID_PROGRESS_SAVE", [
        "nocust" => $nocust,
        "detail" => $detailId,
        "status" => $result["status"],
        "by" => $by,
    ]);
    return $result;
}

function tahfidSubmitSetoran(PDO $pdo, array $req, array $auth): array
{
    $custid = trim((string) ($auth["custid"] ?? ""));
    $detailId = (int) ($req["jadwal_detail_id"] ?? 0);
    if ($detailId < 1) {
        fail(422, "Item jadwal tidak valid");
    }
    $siswa = tahfidFetchSiswaLive($pdo, $custid);
    if (!$siswa) {
        fail(404, "Data siswa tidak ditemukan");
    }
    $code01 = trim((string) $siswa["code01"]);
    $kelas = trim((string) $siswa["kelas"]);

    $stmt = $pdo->prepare("
        SELECT d.id, j.code01, j.kelas
        FROM aka_tahfid_jadwal_detail d
        INNER JOIN aka_tahfid_jadwal j ON j.id = d.jadwal_id
        WHERE d.id = :id
        LIMIT 1
    ");
    $stmt->bindValue(":id", $detailId, PDO::PARAM_INT);
    $stmt->execute();
    $row = $stmt->fetch();
    if (!$row) {
        fail(404, "Item jadwal tidak ditemukan");
    }
    if (trim((string) $row["code01"]) !== $code01) {
        fail(403, "Jadwal ini bukan untuk unit Anda");
    }
    $jadwalKelas = trim((string) $row["kelas"]);
    $allowed = $jadwalKelas === $kelas;
    if (!$allowed) {
        $cek = $pdo->prepare("SELECT id FROM aka_tahfid_percepatan WHERE custid = :c AND kelas_tujuan = :k LIMIT 1");
        $cek->bindValue(":c", $custid, PDO::PARAM_STR);
        $cek->bindValue(":k", $jadwalKelas, PDO::PARAM_STR);
        $cek->execute();
        $allowed = (int) ($cek->fetchColumn() ?: 0) > 0;
    }
    if (!$allowed) {
        fail(403, "Anda belum ditugaskan ke jadwal kelas ini");
    }

    try {
        $ins = $pdo->prepare("
            INSERT INTO aka_tahfid_setoran
                (custid, nocust, nmcust, code01, kelas, jadwal_detail_id, status, created_at)
            VALUES
                (:custid, :nocust, :nmcust, :code01, :kelas, :did, 'setor', NOW())
        ");
        $ins->bindValue(":custid", $custid, PDO::PARAM_STR);
        $ins->bindValue(":nocust", (string) $siswa["nocust"], PDO::PARAM_STR);
        $ins->bindValue(":nmcust", (string) $siswa["nmcust"], PDO::PARAM_STR);
        $ins->bindValue(":code01", $code01, PDO::PARAM_STR);
        $ins->bindValue(":kelas", $kelas, PDO::PARAM_STR);
        $ins->bindValue(":did", $detailId, PDO::PARAM_INT);
        $ins->execute();
    } catch (Throwable $e) {
        if (stripos($e->getMessage(), "Duplicate") !== false) {
            return ["message" => "Setoran ini sudah tercatat"];
        }
        throw $e;
    }
    writeLog("TAHFID_SETORAN", ["custid" => $custid, "detail" => $detailId]);
    try {
        tahfidUpsertProgress($pdo, $siswa, $detailId, 0, 0, true, "Setoran siswi", "siswa");
    } catch (Throwable $e) {
        writeLog("TAHFID_SETORAN_PROGRESS_FAIL", ["custid" => $custid, "message" => $e->getMessage()]);
    }
    return ["message" => "Setoran hafalan tercatat"];
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

    if ($method === "searchSiswa") {
        writeLog("METHOD_SEARCH_SISWA", ["q" => (string) ($req["q"] ?? "")]);
        $data = doSearchSiswa($req, $decoded);
        http_response_code(200);
        echo json_encode(["status" => 200, "data" => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    if ($method === "manageCatatanKepribadian") {
        writeLog("METHOD_CATATAN_KEPRIBADIAN", ["action" => (string) ($req["action"] ?? "list")]);
        $data = doManageCatatanKepribadian($req, $decoded);
        http_response_code(200);
        echo json_encode(["status" => 200, "data" => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    if ($method === "manageTahfid") {
        writeLog("METHOD_TAHFID", ["action" => (string) ($req["action"] ?? "list")]);
        $data = doManageTahfid($req, $decoded);
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
