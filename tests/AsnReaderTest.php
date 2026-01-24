<?php

namespace Asn1Tools\Tests;

use Asn1Tools\AsnEncodingRules;
use Asn1Tools\AsnReader;
use Asn1Tools\Tag\AsnTag;
use Asn1Tools\Tag\TagClass;
use Asn1Tools\Tag\UniversalTag;
use BadMethodCallException;
use BcMath\Number;
use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class AsnReaderTest extends TestCase
{
    public function testReadFirstSequence(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);

        $sequence = $asnReader->readSequence();
        $this->assertSame(UniversalTag::SEQUENCE->value, $sequence->tag->value);
        $this->assertSame(3405, $sequence->length);
        $this->assertSame(3405, strlen($sequence->contents));
    }

    public function testReadSequenceForNonSequenceObject(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);
        $sequence = $asnReader->readSequence();

        $this->expectException(BadMethodCallException::class);
        $sequence->readSequence();
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

        $this->assertSame('1.2.840.113549.1.7.2', $sequence->readObjectIdentifier());
    }

    public function testReadObjectIdentifierForNonObjectIdentifierObject(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);

        $this->expectException(BadMethodCallException::class);
        $asnReader->readObjectIdentifier();
    }

    public function testReadContentWithTagNumber(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);
        $sequence = $asnReader->readSequence();
        $sequence->readObjectIdentifier();

        $content = $sequence->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));
        $this->assertSame(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true)->value, $content->tag->value);
    }

    public function testReadContentWithInvalidTagClass(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);
        $sequence = $asnReader->readSequence();
        $sequence->readObjectIdentifier();

        $this->expectException(InvalidArgumentException::class);
        $sequence->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::Application, 0, true));
    }

    public function testReadContentWithInvalidTagNumber(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);
        $sequence = $asnReader->readSequence();
        $sequence->readObjectIdentifier();

        $this->expectException(InvalidArgumentException::class);
        $sequence->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 1, true));
    }

    public function testReadSignedDataVersion(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);
        $contentInfo = $asnReader->readSequence();
        $contentInfo->readObjectIdentifier();
        $content = $contentInfo->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));

        $signedData = $content->readSequence();
        $version = $signedData->readInteger();

        $this->assertEquals(new Number('1'), $version);
    }

    public function testReadIntegerForNonIntegerObject(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);

        $this->expectException(BadMethodCallException::class);
        $asnReader->readInteger();
    }

    public function testReadSetOf(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);
        $contentInfo = $asnReader->readSequence();
        $contentInfo->readObjectIdentifier();
        $content = $contentInfo->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));

        $signedData = $content->readSequence();
        $signedData->readInteger();
        $digestAlgorithmIdentifiers = $signedData
            ->readSetOf()
            ->readSequence()
            ->readObjectIdentifier();

        $this->assertSame('2.16.840.1.101.3.4.2.1', $digestAlgorithmIdentifiers);
    }

    public function testReadSetOfForNonSetObject(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);

        $this->expectException(BadMethodCallException::class);
        $asnReader->readSetOf();
    }

    public function testReadNull(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);
        $contentInfo = $asnReader->readSequence();
        $contentInfo->readObjectIdentifier();
        $content = $contentInfo->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));

        $signedData = $content->readSequence();
        $signedData->readInteger();
        $digestAlgorithmSet = $signedData
            ->readSetOf()
            ->readSequence();

        $digestAlgorithmSet->readObjectIdentifier();
        $digestAlgorithmSet->readNull();

        // Check that no exception is thrown
        $this->assertTrue(true);
    }

    public function testReadNullForNonNullObject(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);

        $this->expectException(BadMethodCallException::class);
        $asnReader->readNull();
    }

    public function testReadBigInteger(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);
        $contentInfo = $asnReader->readSequence();
        $contentInfo->readObjectIdentifier();
        $content = $contentInfo->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));

        $signedData = $content->readSequence();
        $signedData->readInteger();
        $signedData->readSetOf();
        $signedData->readSequence();

        $certificateSet = $signedData->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));
        $certificate = $certificateSet->readSequence();
        $tbsCertificate = $certificate->readSequence();

        $tbsCertificate->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));
        $serialNumber = $tbsCertificate->readInteger();

        $this->assertEquals(new Number('116642482170122253773863463039760007017'), $serialNumber);
    }

    public function testReadUTF8String(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);
        $contentInfo = $asnReader->readSequence();
        $contentInfo->readObjectIdentifier();
        $content = $contentInfo->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));

        $signedData = $content->readSequence();
        $signedData->readInteger();
        $signedData->readSetOf();
        $signedData->readSequence();

        $certificateSet = $signedData->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));
        $certificate = $certificateSet->readSequence();
        $tbsCertificate = $certificate->readSequence();

        $tbsCertificate->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));
        $tbsCertificate->readInteger();
        $tbsCertificate->readSequence();

        $issuer = $tbsCertificate->readSequence();
        $partOfIssuerName = $issuer->readSetOf()->readSequence();
        $partOfIssuerName->readObjectIdentifier();
        $commonName = $partOfIssuerName->readCharacterString(UniversalTag::UTF8_STRING);

        $this->assertSame('Apple Worldwide Developer Relations Certification Authority', $commonName);
    }

    public function testReadPrintableString(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);
        $contentInfo = $asnReader->readSequence();
        $contentInfo->readObjectIdentifier();
        $content = $contentInfo->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));

        $signedData = $content->readSequence();
        $signedData->readInteger();
        $signedData->readSetOf();
        $signedData->readSequence();

        $certificateSet = $signedData->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));
        $certificate = $certificateSet->readSequence();
        $tbsCertificate = $certificate->readSequence();

        $tbsCertificate->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));
        $tbsCertificate->readInteger();
        $tbsCertificate->readSequence();

        $issuer = $tbsCertificate->readSequence();
        $issuer->readSetOf();
        $issuer->readSetOf();
        $issuer->readSetOf();

        $partOfIssuerName = $issuer->readSetOf()->readSequence();
        $partOfIssuerName->readObjectIdentifier();
        $countryName = $partOfIssuerName->readCharacterString(UniversalTag::PRINTABLE_STRING);

        $this->assertSame('US', $countryName);
    }

    public function testReadUtcTime(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '/fixtures/pkcs7-signed-data.der'), AsnEncodingRules::DER);
        $contentInfo = $asnReader->readSequence();
        $contentInfo->readObjectIdentifier();
        $content = $contentInfo->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));

        $signedData = $content->readSequence();
        $signedData->readInteger();
        $signedData->readSetOf();
        $signedData->readSequence();

        $certificateSet = $signedData->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));
        $certificate = $certificateSet->readSequence();
        $tbsCertificate = $certificate->readSequence();

        $tbsCertificate->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));
        $tbsCertificate->readInteger();
        $tbsCertificate->readSequence();

        $tbsCertificate->readSequence();
        $validity = $tbsCertificate->readSequence();
        $notBefore = $validity->readUtcTime();

        $this->assertEquals(new DateTimeImmutable('2025-11-17 13:21:26+0000'), $notBefore);
    }

}
