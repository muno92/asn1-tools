<?php

namespace Asn1Tools;

use Asn1Tools\Enum\Asn1Tag;
use Asn1Tools\Enum\AsnEncodingRules;
use InvalidArgumentException;

readonly class AsnReader
{
    public Asn1Tag $tag;
    public int $length;
    public string $contents;
    private AsnEncodingRules $encodingRule;

    public function __construct(string $bytes, AsnEncodingRules $encodingRule)
    {
        if ($encodingRule === AsnEncodingRules::BER) {
            throw new InvalidArgumentException('BER encoding is not supported yet.');
        }

        $this->tag = Asn1Tag::from(ord($bytes[0]));
        $lengthBytesCount = $this->parseLength(substr($bytes, 1));

        if ($lengthBytesCount > 127) {
            throw new InvalidArgumentException('Length bytes exceed maximum allowed size.');
        }

        $remainingBytes = strlen($bytes) - 2 - $lengthBytesCount;
        if ($remainingBytes < $this->length) {
            throw new InvalidArgumentException('Insufficient bytes for ASN.1 contents.');
        }

        $this->contents = substr($bytes, 2 + $lengthBytesCount, $this->length);
        $this->encodingRule = $encodingRule;
    }

    public function readSequence(): AsnReader
    {
        return new AsnReader($this->contents, $this->encodingRule);
    }

    private function parseLength(string $bytes): int
    {
        $firstLengthByte = ord($bytes[0]);

        if ($this->lengthIsShortForm($firstLengthByte)) {
            $this->length = $firstLengthByte;
            return 1;
        }

        $lengthBytesCount = $firstLengthByte & 0x7F;

        $length = 0;
        // In long form, the length is specified as multiple bytes
        // e.g. 10000010 (0x82) means the next 2 bytes (16 bits) represent the length
        for ($i = 0; $i < $lengthBytesCount; $i++) {
            $length = ($length << 8) | ord($bytes[1 + $i]);
        }
        $this->length = $length;

        return $lengthBytesCount;
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
