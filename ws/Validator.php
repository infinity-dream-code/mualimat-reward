<?php

class Validator {
    private $data;
    private $rules;
    private $errors = [];

    public function __construct(array $data, array $rules) {
        $this->data = $data;
        $this->rules = $rules;
        $this->validate();
    }

    private function validate() {
        foreach ($this->rules as $field => $ruleString) {
            $rules = preg_split('/\|(?![^\/]*\/)/', $ruleString);

            if (str_contains($field, '*')) {
                $this->validateWildcard($field, $rules);
            } else {
                $value = $this->data[$field] ?? null;
                $this->applyRules($field, $value, $rules);
            }
        }
    }

    private function validateWildcard($field, $rules) {
        $pattern = str_replace(['.', '*'], ['\.', '([0-9]+)'], $field);
        $pattern = "/^" . $pattern . "$/";

        $iterator = new RecursiveIteratorIterator(
            new RecursiveArrayIterator($this->data),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $path => $value) {
            $keys = [];
            for ($depth = 0; $depth <= $iterator->getDepth(); $depth++) {
                $keys[] = $iterator->getSubIterator($depth)->key();
            }
            $fullPath = implode('.', $keys);

            if (preg_match($pattern, $fullPath)) {
                $this->applyRules($fullPath, $value, $rules);
            }
        }
    }

    private function applyRules($field, $value, $rules) {
        // Handle nullable
        if (in_array('nullable', $rules, true) && ($value === null || $value === '')) {
            return;
        }

        foreach ($rules as $rule) {
            $params = null;
            if (str_contains($rule, ':')) {
                [$rule, $params] = explode(':', $rule, 2);
            }

            $method = "validate" . ucfirst($rule);
            if (method_exists($this, $method)) {
                $this->$method($field, $value, $params);
            }
        }
    }

    private function validateRequired($field, $value) {
        if (is_null($value) || $value === '') {
            $this->errors[$field][] = "$field harus diisi.";
        }
    }

    private function validateArray($field, $value) {
        if (!is_array($value)) {
            $this->errors[$field][] = "$field must be an array.";
        }
    }

    private function validateEmail($field, $value) {
        if (!filter_var($value, FILTER_VALIDATE_EMAIL)) {
            $this->errors[$field][] = "$field harus valid.";
        }
    }

    private function validateMin($field, $value, $param) {
        if (is_array($value)) {
            if (count($value) < (int) $param) {
                $this->errors[$field][] = "$field must have at least $param items.";
            }
        } elseif (strlen((string) $value) < (int) $param) {
            $this->errors[$field][] = "$field must be at least $param characters.";
        }
    }

    private function validateMax($field, $value, $param) {
        if (strlen($value) > (int) $param) {
            $this->errors[$field][] = "$field maksimal $param karakter.";
        }
    }

    private function validateNumeric($field, $value) {
        if (!is_numeric($value)) {
            $this->errors[$field][] = "$field harus berisi angka.";
        }
    }

    private function validateIn($field, $value, $param) {
        $allowed = explode(',', $param);
        if (!in_array($value, $allowed)) {
            $this->errors[$field][] = "$field harus salah satu dari: " . implode(', ', $allowed) . ".";
        }
    }

    private function validateRegex($field, $value, $param) {
        if (!preg_match($param, $value)) {
            $this->errors[$field][] = "format $field salah.";
        }
    }

    // ----------------
    // Public methods
    // ----------------

    public function fails(): bool {
        return !empty($this->errors);
    }

    public function passes(): bool {
        return empty($this->errors);
    }

    public function errors(): array {
        return $this->errors;
    }

    public static function make(array $data, array $rules): self {
        return new self($data, $rules);
    }

    public function firstError(): ?string {
        foreach ($this->errors as $fieldErrors) {
            return $fieldErrors[0];
        }
        return null;
    }
}