[![CI](https://github.com/muno92/asn1-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/muno92/asn1-tools/actions/workflows/ci.yml) ![Coverage](coverage.svg)

# asn1-tools

ASN.1 reader and writer (BER/DER) for PHP.

## Requirements

- PHP 8.5+
- ext-bcmath

## Installation

```sh
composer require muno92/asn1-tools
```

## Usage

### Write (DER)

```php
use Asn1Tools\AsnWriter;
use Asn1Tools\Tag\UniversalTag;

$der = new AsnWriter()
    ->writeSequence(function (AsnWriter $writer) {
        $writer
            ->writeObjectIdentifier('1.2.840.113549.1.1.11')
            ->writeInteger(42)
            ->writeCharacterString(UniversalTag::UTF8_STRING, 'hello');
    })
    ->encode();
```

### Read (BER/DER)

```php
use Asn1Tools\AsnEncodingRules;
use Asn1Tools\AsnReader;
use Asn1Tools\Tag\UniversalTag;

$sequence = new AsnReader($der, AsnEncodingRules::DER)->readSequence();

$sequence->readObjectIdentifier();                         // '1.2.840.113549.1.1.11'
$sequence->readInteger();                                  // BcMath\Number(42)
$sequence->readCharacterString(UniversalTag::UTF8_STRING); // 'hello'
```

Integers are returned as `BcMath\Number` so that large values are not truncated.

To inspect an element without knowing its type, use `readElement()`:

```php
$element = new AsnReader("\x02\x02\x01\x2C", AsnEncodingRules::DER)->readElement();

$element->tag->value;    // 0x02 (INTEGER)
$element->headerLength;  // 2 (tag + length bytes)
$element->length;        // 2
$element->contents;      // "\x01\x2C"
```

### PEM

```php
use Asn1Tools\Pem;

$der = Pem::decode(file_get_contents('certificate.pem'));
```

## License

MIT
