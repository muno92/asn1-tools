<?php

namespace Asn1Tools;

class Pem
{
    public static function decode(string $pemData): string
    {
        return base64_decode(implode("\n", array_filter(explode("\n", $pemData), function ($line) {
            return !str_starts_with($line, '-----');
        })));
    }
}
