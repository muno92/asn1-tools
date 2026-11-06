<?php

namespace Asn1Tools;

use Asn1Tools\Tag\AsnTag;
use Asn1Tools\Tag\UniversalTag;
use BcMath\Number;
use Closure;
use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use InvalidArgumentException;

/**
 * Encodes ASN.1 values in DER.
 * (DER is a subset of BER, so the output can also be read as BER.)
 */
class AsnWriter
{
    /**
     * Encoded elements written to this writer, kept separately so that SET OF can sort them.
     *
     * @var list<string>
     */
    private array $elements = [];

    public function encode(): string
    {
        return implode('', $this->elements);
    }

    /**
     * @param Closure(AsnWriter): void $writeChildren
     */
    public function writeSequence(Closure $writeChildren): static
    {
        return $this->writeSequenceWithTagNumber(AsnTag::universal(UniversalTag::SEQUENCE->value), $writeChildren);
    }

    /**
     * @param Closure(AsnWriter): void $writeChildren
     */
    public function writeSequenceWithTagNumber(AsnTag $tag, Closure $writeChildren): static
    {
        $children = new AsnWriter();
        $writeChildren($children);

        return $this->writeObject($tag, $children->encode());
    }

    /**
     * @param Closure(AsnWriter): void $writeChildren
     */
    public function writeSetOf(Closure $writeChildren): static
    {
        $children = new AsnWriter();
        $writeChildren($children);

        // In DER encoding, the elements of SET OF must be sorted in ascending order of their encodings.
        $elements = $children->elements;
        sort($elements, SORT_STRING);

        return $this->writeObject(AsnTag::universal(UniversalTag::SET->value), implode('', $elements));
    }

    public function writeObjectIdentifier(string $objectIdentifier): static
    {
        if (!preg_match('/\A(0|[1-9]\d*)(\.(0|[1-9]\d*))+\z/', $objectIdentifier)) {
            throw new InvalidArgumentException(sprintf('Invalid object identifier: %s.', $objectIdentifier));
        }

        $arcs = array_map(intval(...), explode('.', $objectIdentifier));
        if ($arcs[0] > 2 || ($arcs[0] < 2 && $arcs[1] >= 40)) {
            throw new InvalidArgumentException(sprintf('Invalid object identifier: %s.', $objectIdentifier));
        }

        // The first two arcs are combined into a single sub identifier (X * 40 + Y)
        $subIdentifiers = [$arcs[0] * 40 + $arcs[1], ...array_slice($arcs, 2)];

        $contents = '';
        foreach ($subIdentifiers as $subIdentifier) {
            $contents .= $this->encodeSubIdentifier($subIdentifier);
        }

        return $this->writeObject(AsnTag::universal(UniversalTag::OBJECT_IDENTIFIER->value), $contents);
    }

    public function writeInteger(Number|int $value): static
    {
        $value = $value instanceof Number ? $value : new Number($value);
        if ($value < 0) {
            throw new InvalidArgumentException('Negative integers are not supported yet.');
        }

        $contents = '';
        do {
            [$value, $byte] = $value->divmod(256);
            $contents = chr((int) $byte->value & 0xFF) . $contents;
        } while ($value > 0);

        // The leading bit is the sign bit, so a positive integer starting with 1 needs a leading 0x00
        if ((ord($contents[0]) & 0x80) !== 0) {
            $contents = "\x00" . $contents;
        }

        return $this->writeObject(AsnTag::universal(UniversalTag::INTEGER->value), $contents);
    }

    public function writeNull(): static
    {
        return $this->writeObject(AsnTag::universal(UniversalTag::NULL->value), '');
    }

    public function writeCharacterString(UniversalTag $stringTag, string $value): static
    {
        return $this->writeObject(AsnTag::universal($stringTag->value), $value);
    }

    public function writeUtcTime(DateTimeInterface $dateTime): static
    {
        // In DER encoding, UTC Time is encoded as YYMMDDHHMMSSZ
        return $this->writeObject(
            AsnTag::universal(UniversalTag::UTC_TIME->value),
            $this->toUtc($dateTime)->format('ymdHis\Z'),
        );
    }

    public function writeGeneralizedTime(DateTimeInterface $dateTime): static
    {
        // In DER encoding, Generalized Time is encoded as YYYYMMDDHHMMSSZ
        return $this->writeObject(
            AsnTag::universal(UniversalTag::GENERALIZED_TIME->value),
            $this->toUtc($dateTime)->format('YmdHis\Z'),
        );
    }

    public function writeBitString(BitString $bitString): static
    {
        if ($bitString->unusedBits < 0 || $bitString->unusedBits > 7) {
            throw new InvalidArgumentException('Unused bits must be between 0 and 7.');
        }
        if ($bitString->bytes === '' && $bitString->unusedBits !== 0) {
            throw new InvalidArgumentException('Unused bits must be 0 for an empty bit string.');
        }

        return $this->writeObject(
            AsnTag::universal(UniversalTag::BIT_STRING->value),
            chr($bitString->unusedBits) . $bitString->bytes,
        );
    }

    public function writeOctetString(string $value): static
    {
        return $this->writeObject(AsnTag::universal(UniversalTag::OCTET_STRING->value), $value);
    }

    public function writeBoolean(bool $value): static
    {
        // In DER encoding, TRUE must be encoded as 0xFF
        return $this->writeObject(AsnTag::universal(UniversalTag::BOOLEAN->value), $value ? "\xFF" : "\x00");
    }

    private function writeObject(AsnTag $tag, string $contents): static
    {
        $this->elements[] = chr($tag->value) . $this->encodeLength(strlen($contents)) . $contents;

        return $this;
    }

    /**
     * @param int<0, max> $length
     */
    private function encodeLength(int $length): string
    {
        // Short form: a single byte with bit 8 set to 0
        if ($length < 0x80) {
            return chr($length);
        }

        // Long form: e.g. 10000010 (0x82) followed by 2 bytes representing the length
        // X.690 allows up to 126 length bytes, but pack('J') produces at most 8 bytes (64-bit big endian).
        // This is enough because $length is the strlen() of the contents, which never exceeds PHP_INT_MAX.
        // Leading zero bytes are trimmed since DER requires the minimum number of length bytes.
        $lengthBytes = ltrim(pack('J', $length), "\x00");
        $lengthBytesCount = strlen($lengthBytes);
        if ($lengthBytesCount > 126) {
            throw new InvalidArgumentException('Length exceeds the maximum encodable size.');
        }

        return chr(0x80 | $lengthBytesCount) . $lengthBytes;
    }

    /**
     * Encodes a sub identifier in base 128, setting bit 8 on every byte except the last one.
     */
    private function encodeSubIdentifier(int $subIdentifier): string
    {
        $bytes = chr($subIdentifier & 0x7F);
        $subIdentifier >>= 7;
        while ($subIdentifier > 0) {
            $bytes = chr(0x80 | ($subIdentifier & 0x7F)) . $bytes;
            $subIdentifier >>= 7;
        }

        return $bytes;
    }

    private function toUtc(DateTimeInterface $dateTime): DateTimeInterface
    {
        return DateTimeImmutable::createFromInterface($dateTime)->setTimezone(new DateTimeZone('UTC'));
    }
}
