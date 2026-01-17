<?php

namespace tests;

use Asn1Tools\AsnReader;
use PHPUnit\Framework\TestCase;

class AsnReaderTest extends TestCase
{
    public function testSample(): void
    {
        $asnReader = new AsnReader();

        $this->assertNotNull($asnReader);
    }
}
