<?php

namespace Asn1Tools\Tag;

enum UniversalTag: int
{
    case BOOLEAN = 0x01;
    case INTEGER = 0x02;
    case BIT_STRING = 0x03;
    case OCTET_STRING = 0x04;
    case NULL = 0x05;
    case OBJECT_IDENTIFIER = 0x06;
    case UTF8_STRING = 0x0C;
    case PRINTABLE_STRING = 0x13;
    case IA5_STRING = 0x16;
    case UTC_TIME = 0x17;
    case GENERALIZED_TIME = 0x18;
    case SEQUENCE = 0x30;
    case SET = 0x31;
}
