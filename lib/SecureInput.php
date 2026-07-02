<?php

declare(strict_types=1);

const SECURE_INPUT_MAX_UPLOAD_BYTES = 2_097_152;

const SECURE_INPUT_ALLOWED_UPLOAD_EXT = ['png', 'jpg', 'pdf'];

const SECURE_INPUT_DANGEROUS_EXT = [
    'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phar', 'phps',
    'cgi', 'pl', 'py', 'rb', 'exe', 'dll', 'so', 'sh', 'bash', 'bat', 'cmd',
    'com', 'js', 'mjs', 'html', 'htm', 'xhtml', 'svg', 'asp', 'aspx', 'jsp',
    'htaccess', 'ini', 'config', 'shtml', 'war', 'jar',
];

const SECURE_INPUT_ALLOWED_METHODS = ['login', 'getTahunAkademik', 'submitPrestasi'];

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
    $value = trim($value);
    if ($value === '') {
        return '';
    }
    if (strlen($value) > 100) {
        return null;
    }
    if (!preg_match('/^[a-zA-Z0-9\s.,/+-]+$/u', $value)) {
        return null;
    }
    return $value;
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
