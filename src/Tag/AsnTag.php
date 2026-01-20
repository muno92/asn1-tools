<?php

namespace Asn1Tools\Tag;

readonly class AsnTag
{
    private function __construct(public TagClass $class, public int $value, public bool $constructed = false)
    {
    }

    public static function universal(int $byte, bool $constructed = false): AsnTag
    {
        $tag = new AsnTag(TagClass::Universal, $byte, $constructed);
        $tag->validateUniversalTag();

        return $tag;
    }

    private function validateUniversalTag(): void
    {
        if (!UniversalTag::tryFrom($this->value)) {
            throw new \InvalidArgumentException(sprintf(
                'Invalid Universal tag number: %d.',
                $this->value,
            ));
        }
    }

    public static function specified(TagClass $tagClass, int $byte, AsnTag $expectedTag, bool $constructed = false): AsnTag
    {
        $tag = new AsnTag($tagClass, $byte, $constructed);
        $tag->validateSpecifiedTag($expectedTag);

        return $tag;
    }

    private function validateSpecifiedTag(AsnTag $expected): void
    {
        if ($expected->value !== $this->value) {
            throw new \InvalidArgumentException(sprintf(
                'Expected tag number %d for class %s and constructed %s, but got %d.',
                $expected->value,
                $this->class->name,
                $this->constructed ? 'true' : 'false',
                $this->value,
            ));
        }
    }

    public static function fromEachBits(TagClass $tagClass, int $tagNumber, bool $constructed = false): AsnTag
    {
        // First 2 bits: Tag Class, 3rd bit: Constructed, Last 5 bits: Tag Number
        $byte = $tagClass->value << 6 | ($constructed ? 0b0010_0000 : 0b0000_0000) | ($tagNumber & 0x1F);

        return new AsnTag($tagClass, $byte, $constructed);
    }
}
