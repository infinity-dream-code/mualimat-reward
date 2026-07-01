<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

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
            if ($request->hasFile("file")) {
                $file = $request->file("file");
                if ($file === null || !$file->isValid()) {
                    return response()->json([
                        "status" => 422,
                        "message" => "File upload tidak valid",
                    ], 422);
                }

                $payload = [];
                foreach ($request->except("file") as $key => $value) {
                    if ($value !== null) {
                        $payload[$key] = (string) $value;
                    }
                }
                if (!isset($payload["method"])) {
                    $payload["method"] = $method;
                }

                $response = Http::timeout(30)
                    ->asMultipart()
                    ->attach(
                        "file",
                        file_get_contents($file->getRealPath()),
                        $file->getClientOriginalName()
                    )
                    ->post($wsUrl, $payload);
            } else {
                $payload = $request->all();
                $payload["method"] = $method;

                $response = Http::timeout(30)
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
        } catch (\Throwable $e) {
            return response()->json([
                "status" => 500,
                "message" => "Gagal koneksi ke WS: " . $e->getMessage(),
            ], 500);
        }
    }
}
