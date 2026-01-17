<?php

namespace Asn1Tools;

use Asn1Tools\Enum\Asn1Tag;
use Asn1Tools\Enum\AsnEncodingRules;
use InvalidArgumentException;

readonly class AsnReader
{
    public Asn1Tag $tag;

    public function __construct(string $bytes, AsnEncodingRules $encodingRule)
    {
        if ($encodingRule === AsnEncodingRules::BER) {
            throw new InvalidArgumentException('BER encoding is not supported yet.');
        }

        $this->tag = Asn1Tag::from(ord($bytes[0]));
    }
}
