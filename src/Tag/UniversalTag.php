<?php

namespace Asn1Tools\Tag;

enum UniversalTag: int
{
    case OBJECT_IDENTIFIER = 0x06;
    case SEQUENCE = 0x30;
}
