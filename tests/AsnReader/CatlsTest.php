<?php

namespace Asn1Tools\Tests\AsnReader;

use Asn1Tools\AsnEncodingRules;
use Asn1Tools\AsnReader;
use Asn1Tools\Pem;
use Asn1Tools\Tag\AsnTag;
use Asn1Tools\Tag\TagClass;
use Asn1Tools\Tag\UniversalTag;
use BcMath\Number;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

class CatlsTest extends TestCase
{
    public function testReadFirstSequence(): void
    {
        $asnReader = new AsnReader(Pem::decode(file_get_contents(__DIR__ . '../../fixtures/snakeoil_chain.crt')), AsnEncodingRules::DER);

        $certificate = $asnReader->readSequence();
        $tbsCertificate = $certificate->readSequence();

        $version = $tbsCertificate->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true))->readInteger();
        $this->assertEquals(new Number(2), $version);

        $serialNumber = $tbsCertificate->readInteger();
        $this->assertEquals(new Number(3), $serialNumber);

        // Skip signature
        $tbsCertificate->readSequence();

        $issuer = $tbsCertificate->readSequence();
        $this->assertSame([
            '2.5.4.6' => 'JP',
            '2.5.4.8' => 'Tokyo',
            '2.5.4.7' => 'Chiyoda',
            '2.5.4.10' => 'Local Development',
            '2.5.4.3' => 'Local Development Intermediate CA',
        ], $this->extractName($issuer));

        $validity = $tbsCertificate->readSequence();
        $notBefore = $validity->readutcTime();
        $notAfter = $validity->readutcTime();
        $this->assertEquals(new DateTimeImmutable('2026-05-10 12:52:12+0000'), $notBefore);
        $this->assertEquals(new DateTimeImmutable('2027-05-10 12:52:12+0000'), $notAfter);

        $subject = $tbsCertificate->readSequence();
        $this->assertSame([
            '2.5.4.6' => 'JP',
            '2.5.4.8' => 'Tokyo',
            '2.5.4.7' => 'Chiyoda',
            '2.5.4.10' => 'Local Development',
            '2.5.4.3' => 'localhost',
        ], $this->extractName($subject));
    }

    private function extractName(AsnReader $asnReader): array
    {
        $name = [];
        while (!$asnReader->isEOC) {
            $attribute = $asnReader->readSetOf()->readSequence();
            $oid = $attribute->readObjectIdentifier();
            $value = $attribute->readCharacterString(UniversalTag::UTF8_STRING);
            $name[$oid] = $value;
        }
        return $name;
    }
}
