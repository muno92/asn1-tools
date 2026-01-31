<?php

namespace Asn1Tools\Tests\AsnReader;

use Asn1Tools\AsnEncodingRules;
use Asn1Tools\AsnReader;
use Asn1Tools\Pem;
use Asn1Tools\Tag\AsnTag;
use Asn1Tools\Tag\TagClass;
use Asn1Tools\Tag\UniversalTag;
use PHPUnit\Framework\TestCase;

class PemTest extends TestCase
{
    public function testReadPem(): void
    {
        $asnReader = new AsnReader(Pem::decode(file_get_contents(__DIR__ . '../../fixtures/pkcs7-signed-data_smime_p7s.pem')), AsnEncodingRules::DER);

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
        $commonName = $partOfIssuerName->readCharacterString(UniversalTag::PRINTABLE_STRING);

        $this->assertSame('GlobalSign Root CA - R6', $commonName);
    }
}
