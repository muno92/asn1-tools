<?php

namespace Asn1Tools\Tag;

enum TagClass: int
{
    case Universal = 0b00;
    case Application = 0b01;
    case ContextSpecific = 0b10;
    case Private = 0b11;
}
