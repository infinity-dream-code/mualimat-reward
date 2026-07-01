<?php

class JWT
{
    public function encode(array $payload, string $key, string $alg = "HS256"): string
    {
        $header = ["typ" => "JWT", "alg" => $alg];
        $segments = [
            $this->base64UrlEncode(json_encode($header)),
            $this->base64UrlEncode(json_encode($payload)),
        ];
        $signingInput = implode(".", $segments);
        $signature = $this->sign($signingInput, $key, $alg);
        $segments[] = $this->base64UrlEncode($signature);

        return implode(".", $segments);
    }

    public function decode(string $jwt, string $key, array $allowedAlgs = ["HS256"])
    {
        $parts = explode(".", $jwt);
        if (count($parts) !== 3) {
            throw new RuntimeException("Token JWT tidak valid");
        }

        [$headB64, $payloadB64, $sigB64] = $parts;
        $header = json_decode($this->base64UrlDecode($headB64), true);
        if (!is_array($header) || !isset($header["alg"])) {
            throw new RuntimeException("Header JWT tidak valid");
        }

        $alg = $header["alg"];
        if (!in_array($alg, $allowedAlgs, true)) {
            throw new RuntimeException("Algoritma JWT tidak diizinkan");
        }

        $signingInput = $headB64 . "." . $payloadB64;
        $expected = $this->sign($signingInput, $key, $alg);
        $provided = $this->base64UrlDecode($sigB64);

        if (!hash_equals($expected, $provided)) {
            throw new RuntimeException("Signature JWT tidak valid");
        }

        $payload = json_decode($this->base64UrlDecode($payloadB64), true);
        if (!is_array($payload)) {
            throw new RuntimeException("Payload JWT tidak valid");
        }

        if (isset($payload["exp"]) && time() >= (int) $payload["exp"]) {
            throw new RuntimeException("Token JWT sudah kadaluarsa");
        }

        return $payload;
    }

    private function sign(string $input, string $key, string $alg): string
    {
        return match ($alg) {
            "HS256" => hash_hmac("sha256", $input, $key, true),
            "HS384" => hash_hmac("sha384", $input, $key, true),
            "HS512" => hash_hmac("sha512", $input, $key, true),
            default => throw new RuntimeException("Algoritma tidak didukung: {$alg}"),
        };
    }

    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), "+/", "-_"), "=");
    }

    private function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder > 0) {
            $data .= str_repeat("=", 4 - $remainder);
        }

        $decoded = base64_decode(strtr($data, "-_", "+/"), true);
        if ($decoded === false) {
            throw new RuntimeException("Base64 JWT tidak valid");
        }

        return $decoded;
    }
}
