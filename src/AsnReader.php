<?php

namespace Asn1Tools;

use Asn1Tools\Enum\Asn1Tag;
use Asn1Tools\Enum\AsnEncodingRules;
use InvalidArgumentException;

class AsnReader
{
    public readonly Asn1Tag $tag;
    public readonly int $length;
    public readonly string $contents;
    private readonly AsnEncodingRules $encodingRule;
    private int $lengthBytesCount;

    public function __construct(string $bytes, AsnEncodingRules $encodingRule)
    {
        if ($encodingRule === AsnEncodingRules::BER) {
            throw new InvalidArgumentException('BER encoding is not supported yet.');
        }

        $this->tag = Asn1Tag::from(ord($bytes[0]));
        $this->length = $this->readLength(substr($bytes, 1));

        if ($this->lengthBytesCount > 127) {
            throw new InvalidArgumentException('Length bytes exceed maximum allowed size.');
        }

        $remainingBytes = strlen($bytes) - 2 - $this->lengthBytesCount;
        if ($remainingBytes < $this->length) {
            throw new InvalidArgumentException('Insufficient bytes for ASN.1 contents.');
        }

        $this->contents = substr($bytes, 2 + $this->lengthBytesCount, $this->length);
        $this->encodingRule = $encodingRule;
    }

    public function readSequence(): AsnReader
    {
        return new AsnReader($this->contents, $this->encodingRule);
    }

    private function readLength(string $bytes): int
    {
        $firstLengthByte = ord($bytes[0]);

        if ($this->lengthIsShortForm($firstLengthByte)) {
            $this->lengthBytesCount = 1;
            return $firstLengthByte;
        }

        $this->lengthBytesCount = $firstLengthByte & 0x7F;

        $length = 0;
        // In long form, the length is specified as multiple bytes
        // e.g. 10000010 (0x82) means the next 2 bytes (16 bits) represent the length
        for ($i = 0; $i < $this->lengthBytesCount; $i++) {
            $length = ($length << 8) | ord($bytes[1 + $i]);
        }
        return $length;
    }

    /**
     * Checks if the given length is in short form.
     * (In short form, bit 8 is 0, indicating the length is represented in a single byte.)
     *
     * @param int $length The length value to evaluate.
     * @return bool Returns true if the length is in short form, false otherwise.
     */
    private function lengthIsShortForm(int $length): bool
    {
        return $length & 0x80 === 0;
    }
}
