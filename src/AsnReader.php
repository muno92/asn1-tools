<?php

namespace Asn1Tools;

use Asn1Tools\Tag\AsnTag;
use Asn1Tools\Tag\TagClass;
use Asn1Tools\Tag\UniversalTag;
use BadMethodCallException;
use BcMath\Number;
use Generator;
use InvalidArgumentException;
use UnexpectedValueException;

class AsnReader
{
    public private(set) AsnTag $tag;
    public private(set) int $length;
    public private(set) string $contents;
    private int $headerLength;
    private int $totalLength {
        get => $this->headerLength + $this->length;
    }
    private readonly AsnEncodingRules $encodingRule;
    private readonly string $bytes;
    private int $offset;
    private ?AsnTag $expectedTag;
    private bool $isEOC {
        get => $this->offset === $this->totalLength;
    }

    public function __construct(string $bytes, AsnEncodingRules $encodingRule, ?AsnTag $expectedTag = null)
    {
        if ($encodingRule === AsnEncodingRules::BER) {
            throw new InvalidArgumentException('BER encoding is not supported yet.');
        }

        $this->bytes = $bytes;
        $this->offset = 0;
        $this->encodingRule = $encodingRule;
        $this->expectedTag = $expectedTag;
    }

    public function readSequence(): AsnReader
    {
        $nextObject = $this->readNextObject(AsnTag::universal(UniversalTag::SEQUENCE->value));

        return $nextObject;
    }

    public function readSequenceWithTagNumber(AsnTag $tag): AsnReader
    {
        return $this->readNextObject($tag);
    }

    public function readSetOf(): AsnReader
    {
        return $this->readNextObject(AsnTag::universal(UniversalTag::SET->value));
    }

    public function readObjectIdentifier(): string
    {
        $objectIdentifier = $this->readNextObject(AsnTag::universal(UniversalTag::OBJECT_IDENTIFIER->value));

        $subIdentifiers = [];
        $subIdentifier = 0;
        foreach ($objectIdentifier->enumerateContentBytes() as $i => $byte) {
            if ($i === 0) {
                $subIdentifiers[] = intdiv($byte, 40);
                $subIdentifiers[] = $byte % 40;
                continue;
            }

            $subIdentifier = ($subIdentifier << 7) | ($byte & 0x7F);

            $isEndOfSubIdentifier = ($byte & 0x80) === 0;
            if ($isEndOfSubIdentifier) {
                $subIdentifiers[] = $subIdentifier;
                $subIdentifier = 0;
            }
        }

        return implode('.', $subIdentifiers);
    }

    /**
     * Reads an INTEGER value from the ASN.1 encoded data.
     * * Integers are returned as BcMath\Number to accommodate large values that may exceed PHP's integer limits.
     *
     * @return Number
     */
    public function readInteger(): Number
    {
        $integer = $this->readNextObject(AsnTag::universal(UniversalTag::INTEGER->value));

        $value = new Number(0);
        foreach ($integer->enumerateContentBytes() as $i => $byte) {
            if ($i === 0) {
                $isNegative = ($byte & 0x80) !== 0;
                if ($isNegative) {
                    throw new UnexpectedValueException('Negative integers are not supported yet.');
                }

                $value = new Number($byte);
                continue;
            }
            $value = $value * 256 + new Number($byte);
        }

        return $value;
    }

    public function readNull(): void
    {
        $this->readNextObject(AsnTag::universal(UniversalTag::NULL->value));
    }

    public function enumerateContentBytes(): Generator
    {
        while (!$this->isEOC) {
            yield $this->readByte();
        }
    }

    private function readByte(): int
    {
        return ord($this->bytes[$this->offset++]);
    }

    private function readHeader(): void
    {
        $this->tag = $this->expectedTag !== null && $this->expectedTag->class !== TagClass::Universal
            ? AsnTag::specified($this->expectedTag->class, $this->readByte(), $this->expectedTag, $this->expectedTag->constructed)
            : AsnTag::universal($this->readByte());
        $this->length = $this->readLength();
        $this->headerLength = $this->offset;
        $this->contents = substr($this->bytes, $this->offset, $this->length);

        if (strlen($this->contents) < $this->length) {
            throw new InvalidArgumentException('Insufficient bytes for ASN.1 contents.');
        }
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

    private function readNextObject(AsnTag $expectedTag): AsnReader
    {
        $reader = new AsnReader($this->readRemainingBytes(), $this->encodingRule, $expectedTag);
        $reader->readHeader();
        $reader->validateTag($expectedTag);

        $this->skipParsedBytes($reader);

        return $reader;
    }

    private function readRemainingBytes(): string
    {
        return substr($this->bytes, $this->offset);
    }

    private function skipParsedBytes(AsnReader $parsedContent): void
    {
        $this->offset += $parsedContent->totalLength;
    }

    private function validateTag(AsnTag $expectedTag): void
    {
        if ($this->tag->value !== $expectedTag->value) {
            throw new BadMethodCallException(sprintf(
                'Expected tag number %d, but got %d',
                $expectedTag->value,
                $this->tag->value,
            ));
        }
    }
}
