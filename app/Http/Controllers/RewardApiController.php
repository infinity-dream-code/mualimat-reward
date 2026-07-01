<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Http;
use RuntimeException;
use Throwable;

class RewardApiController extends Controller
{
    public function handle(Request $request): JsonResponse
    {
        $wsUrl = trim((string) env("WS_URL", ""));
        if ($wsUrl === "") {
            return response()->json([
                "status" => 500,
                "message" => "WS_URL belum diatur di .env",
            ], 500);
        }

        $method = trim((string) $request->input("method", ""));
        if ($method === "") {
            return response()->json([
                "status" => 422,
                "message" => "Method wajib diisi",
            ], 422);
        }

        try {
            $payload = $request->except("file");
            $payload["method"] = $method;

            if ($method === "submitPrestasi" && $request->hasFile("file")) {
                $file = $request->file("file");
                if ($file === null || !$file->isValid()) {
                    return response()->json([
                        "status" => 422,
                        "message" => "File upload tidak valid",
                    ], 422);
                }

                $token = (string) $request->input("token", "");
                $decoded = $this->decodeToken($token);
                if ($decoded === null) {
                    return response()->json([
                        "status" => 401,
                        "message" => "Token JWT tidak valid",
                    ], 401);
                }

                $nocust = trim((string) ($decoded["nocust"] ?? ""));
                if ($nocust === "") {
                    return response()->json([
                        "status" => 401,
                        "message" => "Sesi tidak valid, silakan login ulang",
                    ], 401);
                }

                $jenis = trim((string) $request->input("jenis_prestasi", ""));
                $ket = trim((string) $request->input("keterangan", ""));
                $payload["url"] = $this->storeUploadFile($file, $nocust, $jenis, $ket);

                $response = Http::connectTimeout(5)
                    ->timeout(20)
                    ->retry(1, 150)
                    ->asForm()
                    ->acceptJson()
                    ->post($wsUrl, $payload);
            } elseif ($request->hasFile("file")) {
                $file = $request->file("file");
                if ($file === null || !$file->isValid()) {
                    return response()->json([
                        "status" => 422,
                        "message" => "File upload tidak valid",
                    ], 422);
                }

                foreach ($payload as $key => $value) {
                    if ($value !== null) {
                        $payload[$key] = (string) $value;
                    }
                }

                $response = Http::connectTimeout(5)
                    ->timeout(20)
                    ->retry(1, 150)
                    ->asMultipart()
                    ->attach(
                        "file",
                        file_get_contents($file->getRealPath()),
                        $file->getClientOriginalName()
                    )
                    ->post($wsUrl, $payload);
            } else {
                $payload["method"] = $method;

                $response = Http::connectTimeout(5)
                    ->timeout(20)
                    ->retry(1, 150)
                    ->asForm()
                    ->acceptJson()
                    ->post($wsUrl, $payload);
            }

            $json = $response->json();
            if (is_array($json)) {
                $status = (int) ($json["status"] ?? $response->status());
                return response()->json($json, $status > 0 ? $status : 200);
            }

            $raw = preg_replace('/\s+/', ' ', (string) $response->body());
            $raw = trim((string) $raw);
            $raw = mb_substr($raw, 0, 220);

            return response()->json([
                "status" => $response->status(),
                "message" => "Respons WS bukan JSON | HTTP: " . $response->status() . " | RAW: " . $raw,
                "raw" => $response->body(),
            ], $response->status());
        } catch (Throwable $e) {
            return response()->json([
                "status" => 500,
                "message" => $e->getMessage(),
            ], 500);
        }
    }

    private function storeUploadFile(UploadedFile $file, string $nocust, string $jenis, string $ket): string
    {
        if ($file->getSize() > 2 * 1024 * 1024) {
            throw new RuntimeException("Ukuran file maksimal 2MB");
        }

        $ext = strtolower((string) $file->getClientOriginalExtension());
        if (!in_array($ext, ["png", "jpg", "jpeg", "pdf"], true)) {
            throw new RuntimeException("Format file harus png/jpg/jpeg/pdf");
        }

        $mime = strtolower((string) $file->getMimeType());
        if (!in_array($mime, ["image/png", "image/jpeg", "application/pdf"], true)) {
            throw new RuntimeException("Tipe file tidak valid");
        }

        $folder = public_path("uploads/" . $nocust);
        if (!is_dir($folder) && !mkdir($folder, 0755, true) && !is_dir($folder)) {
            throw new RuntimeException("Gagal membuat folder upload: " . $folder);
        }

        $base = $this->slugify($jenis) . "_" . $this->slugify($ket);
        $base = trim($base, "_");
        if ($base === "") {
            $base = "prestasi";
        }

        $fileName = $base . "_" . time() . "." . $ext;
        $file->move($folder, $fileName);

        return url("uploads/" . $nocust . "/" . $fileName);
    }

    private function slugify(string $value): string
    {
        $value = strtolower(trim($value));
        $value = preg_replace('/[^a-z0-9]+/', "_", $value);
        return trim((string) $value, "_");
    }

    private function decodeToken(string $token): ?array
    {
        if ($token === "") {
            return null;
        }

        try {
            require_once base_path("lib/jwt.php");
            $jwt = new \JWT();
            $decoded = $jwt->decode($token, (string) env("JWT_KEY"), ["HS256"]);
            return is_array($decoded) ? $decoded : null;
        } catch (Throwable) {
            return null;
        }
    }
}
