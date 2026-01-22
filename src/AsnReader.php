<?php

namespace Asn1Tools;

use Asn1Tools\Tag\AsnTag;
use Asn1Tools\Tag\TagClass;
use InvalidArgumentException;

class AsnReader
{
    public readonly AsnTag $tag;
    private readonly int $headerLength;
    public readonly int $length;
    private int $totalLength {
        get => $this->headerLength + $this->length;
    }
    public readonly string $contents;
    private readonly AsnEncodingRules $encodingRule;
    private readonly string $bytes;
    private int $offset;

    public function __construct(string $bytes, AsnEncodingRules $encodingRule, ?AsnTag $expectedTag = null)
    {
        if ($encodingRule === AsnEncodingRules::BER) {
            throw new InvalidArgumentException('BER encoding is not supported yet.');
        }

        $this->bytes = $bytes;
        $this->offset = 0;
        $this->encodingRule = $encodingRule;

        $this->tag = $expectedTag !== null && $expectedTag->class !== TagClass::Universal
            ? AsnTag::specified($expectedTag->class, $this->readByte(), $expectedTag, $expectedTag->constructed)
            : AsnTag::universal($this->readByte());
        $this->length = $this->readLength();
        $this->headerLength = $this->offset;
        $this->contents = substr($bytes, $this->offset, $this->length);

        if (strlen($this->contents) < $this->length) {
            throw new InvalidArgumentException('Insufficient bytes for ASN.1 contents.');
        }
    }

    public function readSequence(): AsnReader
    {
        return new AsnReader($this->readRemainingBytes(), $this->encodingRule);
    }

    public function readSequenceWithTagNumber(AsnTag $tag): AsnReader
    {
        return new AsnReader($this->readRemainingBytes(), $this->encodingRule, $tag);
    }

    public function readObjectIdentifier(): string
    {
        $oid = [];

        $firstByte = $this->readByte();
        $oid[] = intdiv($firstByte, 40);
        $oid[] = $firstByte % 40;

        while ($this->offset < $this->totalLength) {
            $value = 0;
            do {
                $byte = $this->readByte();
                $value = ($value << 7) | ($byte & 0x7F);
            } while (($byte & 0x80) !== 0);
            $oid[] = $value;
        }

        return implode('.', $oid);
    }

    public function readInteger(): int
    {
        $integer = new AsnReader($this->readRemainingBytes(), $this->encodingRule);

        $firstByte = $integer->readByte();
        $isNegative = ($firstByte & 0x80) !== 0;
        if ($isNegative) {
            throw new \UnexpectedValueException('Negative integers are not supported now.');
        }

        $value = $firstByte;
        for ($i = 1; $i < $integer->length; $i++) {
            $value = ($value << 8) | $integer->readByte();
        }

        return $value;
    }

    public function readByte(): int
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

    private function readRemainingBytes(): string
    {
        return substr($this->bytes, $this->offset);
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
