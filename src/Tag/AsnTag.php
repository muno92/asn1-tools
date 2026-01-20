<?php

namespace Asn1Tools\Tag;

readonly class AsnTag
{
    public int $value;

    public function __construct(public TagClass $class, int $number)
    {
        if ($this->class === TagClass::Universal) {
            // Check if the number corresponds to a known UniversalTag
            $this->value = UniversalTag::from($number)->value;
            return;
        }

        $firstTwoBitsOfTagClass = $this->class->value << 6;
        $firstTwoBitsOfNumber = $number & 0xC0;
        if ($firstTwoBitsOfTagClass !== $firstTwoBitsOfNumber) {
            throw new \InvalidArgumentException(sprintf(
                'First two bits of tag class expect to be %02b but found %02b for tag number %d in class %s.',
                $this->class->value,
                $firstTwoBitsOfNumber >> 6,
                $number,
                $this->class->name
            ));
        }

        $this->value = $number;
    }
}
