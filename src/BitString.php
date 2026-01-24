<?php

namespace Asn1Tools;

readonly class BitString
{
    public function __construct(
        public string $bytes,
        public int $unusedBits,
    ) {
    }
}
