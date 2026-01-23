<?php

namespace Asn1Tools\Tag;

enum UniversalTag: int
{
    case INTEGER = 0x02;
    case NULL = 0x05;
    case OBJECT_IDENTIFIER = 0x06;
    case SEQUENCE = 0x30;
    case SET = 0x31;
}
