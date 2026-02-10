<?php

namespace Asn1Tools\Tests\AsnReader;

use Asn1Tools\AsnEncodingRules;
use Asn1Tools\AsnReader;
use Asn1Tools\Tag\AsnTag;
use Asn1Tools\Tag\TagClass;
use Asn1Tools\Tag\UniversalTag;
use BcMath\Number;
use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class BerTest extends TestCase
{
    public function testReadSequenceObjectIdentifier(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '../../fixtures/pkcs7-signed-data.ber'), AsnEncodingRules::BER);
        $sequence = $asnReader->readSequence();

        $this->assertSame('1.2.840.113549.1.7.2', $sequence->readObjectIdentifier());
    }

    public function testReadBerAsDer(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $asnReader = new AsnReader(file_get_contents(__DIR__ . '../../fixtures/pkcs7-signed-data.ber'), AsnEncodingRules::DER);
        $asnReader->readSequence();
    }

    public function testReadIndefiniteLengthSequence(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '../../fixtures/pkcs7-signed-data.ber'), AsnEncodingRules::BER);
        $contentInfo = $asnReader->readSequence();
        $contentInfo->readObjectIdentifier();
        $content = $contentInfo->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));

        $signedData = $content->readSequence();
        $signedData->readInteger();
        $signedData->readSetOf();
        // This sequence has an indefinite length encoding
        $signedData->readSequence();

        $certificateSet = $signedData->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));
        $certificate = $certificateSet->readSequence();
        $tbsCertificate = $certificate->readSequence();

        $tbsCertificate->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));
        $serialNumber = $tbsCertificate->readInteger();

        $this->assertEquals(new Number('136556853852351620597131812378341834969'), $serialNumber);
    }

    public function testReadSignerInfo(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '../../fixtures/pkcs7-signed-data.ber'), AsnEncodingRules::BER);
        $contentInfo = $asnReader->readSequence();
        $contentInfo->readObjectIdentifier();
        $content = $contentInfo->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));

        $signedData = $content->readSequence();
        $signedData->readInteger();
        $signedData->readSetOf();
        $signedData->readSequence();

        // Long indefinite length sequence
        $signedData->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));

        $signerInfo = $signedData->readSetOf()->readSequence();
        $signerInfo->readInteger();

        $commonName = $signerInfo->readSequence()->readSequence()->readSetOf()->readSequence();
        $commonName->readObjectIdentifier();

        $this->assertSame('Apple Worldwide Developer Relations Certification Authority', $commonName->readCharacterString(UniversalTag::UTF8_STRING));
    }

    public function testReadUTCTime(): void
    {
        $asnReader = new AsnReader(file_get_contents(__DIR__ . '../../fixtures/pkcs7-signed-data.ber'), AsnEncodingRules::BER);
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

        $this->assertEquals(new DateTimeImmutable('2024-08-22 09:39:23+0000'), $notBefore);
    }
}
