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
    private string $bytes;
    private int $offset;

    public function __construct(string $bytes, AsnEncodingRules $encodingRule)
    {
        if ($encodingRule === AsnEncodingRules::BER) {
            throw new InvalidArgumentException('BER encoding is not supported yet.');
        }

        $this->bytes = $bytes;
        $this->offset = 0;
        $this->encodingRule = $encodingRule;

        $this->tag = Asn1Tag::from($this->readByte());
        $this->length = $this->readLength();
        $this->contents = substr($bytes, $this->offset, $this->length);

        if (strlen($this->contents) < $this->length) {
            throw new InvalidArgumentException('Insufficient bytes for ASN.1 contents.');
        }
    }

    public function readSequence(): AsnReader
    {
        return new AsnReader($this->contents, $this->encodingRule);
    }

    private function readByte(): int
    {
        return ord($this->bytes[$this->offset++]);
    }

    private function readLength(): int
    {
        $firstLengthByte = $this->readByte();

        if ($this->lengthIsShortForm($firstLengthByte)) {
            return $firstLengthByte;
        }

        $lengthBytesCount = $firstLengthByte & 0x7F;

        $length = 0;
        // In long form, the length is specified as multiple bytes
        // e.g. 10000010 (0x82) means the next 2 bytes (16 bits) represent the length
        for ($i = 0; $i < $lengthBytesCount; $i++) {
            $length = ($length << 8) | $this->readByte();
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
        return ($length & 0x80) === 0;
    }
}
