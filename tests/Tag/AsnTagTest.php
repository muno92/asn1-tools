<?php

namespace Asn1Tools\Tests\Tag;

use Asn1Tools\Tag\AsnTag;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class AsnTagTest extends TestCase
{
    public function testInvalidUniversalTag(): void
    {
        $this->expectException(InvalidArgumentException::class);
        AsnTag::universal(0x99);
    }
}
