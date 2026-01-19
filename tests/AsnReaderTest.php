<?php

namespace Asn1Tools\Tests;

use Asn1Tools\AsnEncodingRules;
use Asn1Tools\AsnReader;
use Asn1Tools\Tag\TagClass;
use Asn1Tools\Tag\UniversalTag;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class AsnReaderTest extends TestCase
{
    public function testReadFirstSequence(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);

        $this->assertSame(UniversalTag::SEQUENCE->value, $asnReader->tag->value);
        $this->assertSame(3405, $asnReader->length);
        $this->assertSame(3405, strlen($asnReader->contents));
    }

    public function testBerEncodingNotSupported(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::BER);
    }

    public function testReadSequenceObjectIdentifier(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);
        $sequence = $asnReader->readSequence();

        $this->assertSame(UniversalTag::OBJECT_IDENTIFIER->value, $sequence->tag->value);
        $this->assertSame('1.2.840.113549.1.7.2', $sequence->readObjectIdentifier());
    }

    public function testReadContentWithTagNumber(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);
        $sequence = $asnReader->readSequence();
        $sequence->readObjectIdentifier();

        $content = $sequence->readSequenceWithTagNumber(TagClass::ContextSpecific, 0);
        $this->assertSame(0, $content->tag->value);
    }

    public function testReadContentWithInvalidTagNumber(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);
        $sequence = $asnReader->readSequence();
        $sequence->readObjectIdentifier();

        $this->expectException(InvalidArgumentException::class);
        $sequence->readSequenceWithTagNumber(TagClass::ContextSpecific, 1);
    }
}
