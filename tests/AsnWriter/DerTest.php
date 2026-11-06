<?php

namespace Asn1Tools\Tests\AsnWriter;

use Asn1Tools\AsnEncodingRules;
use Asn1Tools\AsnReader;
use Asn1Tools\AsnWriter;
use Asn1Tools\BitString;
use Asn1Tools\Pem;
use Asn1Tools\Tag\AsnTag;
use Asn1Tools\Tag\TagClass;
use Asn1Tools\Tag\UniversalTag;
use BcMath\Number;
use DateTimeImmutable;
use Generator;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class DerTest extends TestCase
{
    public function testWriteEmptySequence(): void
    {
        $this->assertSame("\x30\x00", new AsnWriter()->writeSequence(function () {
        })->encode());
    }

    public function testWriteSequence(): void
    {
        $encoded = new AsnWriter()->writeSequence(function (AsnWriter $writer) {
            $writer->writeInteger(1)->writeNull();
        })->encode();

        $this->assertSame("\x30\x05\x02\x01\x01\x05\x00", $encoded);
    }

    public function testWriteSequenceWithTagNumber(): void
    {
        $encoded = new AsnWriter()->writeSequenceWithTagNumber(
            AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true),
            function (AsnWriter $writer) {
                $writer->writeInteger(2);
            },
        )->encode();

        $this->assertSame("\xA0\x03\x02\x01\x02", $encoded);
    }

    public function testWriteSetOfSortsElements(): void
    {
        $encoded = new AsnWriter()->writeSetOf(function (AsnWriter $writer) {
            $writer->writeInteger(256)->writeInteger(3)->writeInteger(1);
        })->encode();

        $this->assertSame("\x31\x0A\x02\x01\x01\x02\x01\x03\x02\x02\x01\x00", $encoded);
    }

    public function testWriteLongFormLength(): void
    {
        $encoded = new AsnWriter()->writeOctetString(str_repeat('a', 300))->encode();

        $this->assertSame("\x04\x82\x01\x2C", substr($encoded, 0, 4));
        $this->assertSame(304, strlen($encoded));
    }

    public function testWriteLengthBoundary(): void
    {
        $this->assertSame("\x04\x7F", substr(new AsnWriter()->writeOctetString(str_repeat('a', 127))->encode(), 0, 2));
        $this->assertSame("\x04\x81\x80", substr(new AsnWriter()->writeOctetString(str_repeat('a', 128))->encode(), 0, 3));
    }

    /**
     * @return Generator<string, array{string, string}>
     */
    public static function objectIdentifierProvider(): Generator
    {
        yield 'pkcs7-signedData' => ['1.2.840.113549.1.7.2', "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02"];
        yield 'sha256' => ['2.16.840.1.101.3.4.2.1', "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01"];
        yield 'commonName' => ['2.5.4.3', "\x06\x03\x55\x04\x03"];
        yield 'first sub identifier over 127' => ['2.999.3', "\x06\x03\x88\x37\x03"];
    }

    #[DataProvider('objectIdentifierProvider')]
    public function testWriteObjectIdentifier(string $objectIdentifier, string $expected): void
    {
        $this->assertSame($expected, new AsnWriter()->writeObjectIdentifier($objectIdentifier)->encode());
    }

    /**
     * @return Generator<string, array{string}>
     */
    public static function invalidObjectIdentifierProvider(): Generator
    {
        yield 'single arc' => ['1'];
        yield 'empty arc' => ['1..2'];
        yield 'leading zero' => ['1.02'];
        yield 'not a number' => ['1.a'];
        yield 'first arc over 2' => ['3.1'];
        yield 'second arc over 39' => ['1.40'];
    }

    #[DataProvider('invalidObjectIdentifierProvider')]
    public function testWriteInvalidObjectIdentifier(string $objectIdentifier): void
    {
        $this->expectException(InvalidArgumentException::class);
        new AsnWriter()->writeObjectIdentifier($objectIdentifier);
    }

    /**
     * @return Generator<string, array{Number|int, string}>
     */
    public static function integerProvider(): Generator
    {
        yield 'zero' => [0, "\x02\x01\x00"];
        yield 'one byte' => [127, "\x02\x01\x7F"];
        yield 'leading bit set' => [128, "\x02\x02\x00\x80"];
        yield 'two bytes' => [256, "\x02\x02\x01\x00"];
        yield 'big integer' => [
            new Number('116642482170122253773863463039760007017'),
            "\x02\x10" . hex2bin('57c0866126b355aeb829332610a6ff69'),
        ];
    }

    #[DataProvider('integerProvider')]
    public function testWriteInteger(Number|int $value, string $expected): void
    {
        $this->assertSame($expected, new AsnWriter()->writeInteger($value)->encode());
    }

    public function testWriteNegativeInteger(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new AsnWriter()->writeInteger(-1);
    }

    public function testWriteNull(): void
    {
        $this->assertSame("\x05\x00", new AsnWriter()->writeNull()->encode());
    }

    public function testWriteCharacterString(): void
    {
        $this->assertSame("\x13\x02US", new AsnWriter()->writeCharacterString(UniversalTag::PRINTABLE_STRING, 'US')->encode());
        $this->assertSame("\x0C\x06東", substr(new AsnWriter()->writeCharacterString(UniversalTag::UTF8_STRING, '東京')->encode(), 0, 5));
    }

    public function testWriteUtcTime(): void
    {
        $encoded = new AsnWriter()->writeUtcTime(new DateTimeImmutable('2025-11-17 22:21:26+0900'))->encode();

        $this->assertSame("\x17\x0D251117132126Z", $encoded);
    }

    public function testWriteGeneralizedTime(): void
    {
        $encoded = new AsnWriter()->writeGeneralizedTime(new DateTimeImmutable('2076-01-19 06:02:47+0000'))->encode();

        $this->assertSame("\x18\x0F20760119060247Z", $encoded);
    }

    public function testWriteBitString(): void
    {
        $this->assertSame("\x03\x03\x07\xFF\x80", new AsnWriter()->writeBitString(new BitString("\xFF\x80", 7))->encode());
        $this->assertSame("\x03\x01\x00", new AsnWriter()->writeBitString(new BitString('', 0))->encode());
    }

    public function testWriteBitStringWithInvalidUnusedBits(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new AsnWriter()->writeBitString(new BitString("\xFF", 8));
    }

    public function testWriteEmptyBitStringWithUnusedBits(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new AsnWriter()->writeBitString(new BitString('', 1));
    }

    public function testWriteOctetString(): void
    {
        $this->assertSame("\x04\x02\x30\x00", new AsnWriter()->writeOctetString("\x30\x00")->encode());
    }

    public function testWriteBoolean(): void
    {
        $this->assertSame("\x01\x01\xFF", new AsnWriter()->writeBoolean(true)->encode());
        $this->assertSame("\x01\x01\x00", new AsnWriter()->writeBoolean(false)->encode());
    }

    public function testReencodeCertificateName(): void
    {
        $certificate = new AsnReader(Pem::decode(file_get_contents(__DIR__ . '../../fixtures/snakeoil_chain.crt')), AsnEncodingRules::DER)->readSequence();
        $tbsCertificate = $certificate->readSequence();
        $tbsCertificate->readSequenceWithTagNumber(AsnTag::fromEachBits(TagClass::ContextSpecific, 0, true));
        $tbsCertificate->readInteger();
        $tbsCertificate->readSequence();
        $issuer = $tbsCertificate->readSequence();

        $encoded = new AsnWriter()->writeSequence(function (AsnWriter $writer) {
            foreach (
                [
                    '2.5.4.6' => 'JP',
                    '2.5.4.8' => 'Tokyo',
                    '2.5.4.7' => 'Chiyoda',
                    '2.5.4.10' => 'Local Development',
                    '2.5.4.3' => 'Local Development Intermediate CA',
                ] as $oid => $value
            ) {
                $writer->writeSetOf(function (AsnWriter $writer) use ($oid, $value) {
                    $writer->writeSequence(function (AsnWriter $writer) use ($oid, $value) {
                        $writer->writeObjectIdentifier((string) $oid)->writeCharacterString(UniversalTag::UTF8_STRING, $value);
                    });
                });
            }
        })->encode();

        $this->assertSame($issuer->contents, new AsnReader($encoded, AsnEncodingRules::DER)->readSequence()->contents);
    }
}
