<?php

namespace Asn1Tools\Tests;

use Asn1Tools\AsnReader;
use Asn1Tools\Enum\Asn1Tag;
use Asn1Tools\Enum\AsnEncodingRules;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class AsnReaderTest extends TestCase
{
    public function testReadFirstSequence(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);

        $this->assertSame(Asn1Tag::SEQUENCE, $asnReader->tag);
        $this->assertSame(3405, $asnReader->length);
        $this->assertSame(3405, strlen($asnReader->contents));
    }

    public function testBerEncodingNotSupported(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::BER);
    }
}
