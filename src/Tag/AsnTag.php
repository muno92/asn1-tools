<?php

namespace Asn1Tools\Tag;

readonly class AsnTag
{
    public int $value;

    public function __construct(public TagClass $class = TagClass::Universal, int $number)
    {
        if ($this->class === TagClass::Universal) {
            // Check if the number corresponds to a known UniversalTag
            $this->value = UniversalTag::from($number)->value;
            return;
        }
        $this->value = $number;
    }
}
