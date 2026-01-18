<?php

namespace Asn1Tools\Enum;

enum Asn1Tag: int
{
    case OBJECT_IDENTIFIER = 0x06;
    case SEQUENCE = 0x30;
}
