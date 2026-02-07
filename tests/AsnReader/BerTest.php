<?php

namespace Asn1Tools\Tests\AsnReader;

use Asn1Tools\AsnEncodingRules;
use Asn1Tools\AsnReader;
use PHPUnit\Framework\TestCase;

class BerTest extends TestCase
{
    public function testReadSequenceObjectIdentifier(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '../../fixtures/pkcs7-signed-data.ber'), AsnEncodingRules::BER);
        $sequence = $asnReader->readSequence();

        $this->assertSame('1.2.840.113549.1.7.2', $sequence->readObjectIdentifier());
    }
}
