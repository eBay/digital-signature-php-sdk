<?php

namespace Ebay\DigitalSignature;

require 'vendor/autoload.php';

use PHPUnit\Framework\TestCase;

class SignatureTest extends TestCase {
    const CONFIG_FILE_RSA = "tests/test-rsa-config.json";
    const CONFIG_FILE_ED25519 = "tests/test-ed25519-config.json";


    public function testGenerateSignatureHeadersRSA(): void {
        $signature = new Signature(SignatureTest::CONFIG_FILE_RSA);
        $headers = array("Foo => Bar");
        $endpoint = "https://localhost/foo";
        $method = "POST";
        $body = '{"hello": "world"}';

        $allHeaders = $signature->generateSignatureHeaders($headers, $endpoint, $method, $body);

        $this->assertArrayHasKey("Content-Digest", $allHeaders);
        $this->assertArrayHasKey("x-ebay-signature-key", $allHeaders);
        $this->assertArrayHasKey("Signature-Input", $allHeaders);
        $this->assertArrayHasKey("Signature", $allHeaders);
        $this->assertArrayHasKey("x-ebay-enforce-signature", $allHeaders);

        $this->assertEquals("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:", $allHeaders["Content-Digest"]);
        $this->assertEquals("jwe", $allHeaders["x-ebay-signature-key"]);
        $this->assertStringStartsWith('sig1=("content-digest" "x-ebay-signature-key" "@method" "@path" "@authority");created=', $allHeaders["Signature-Input"]);
        $this->assertStringStartsWith("sig1=:", $allHeaders["Signature"]);
        $this->assertEquals("true", $allHeaders["x-ebay-enforce-signature"]);
    }

    public function testGenerateSignatureHeadersEd25519(): void {
        $signature = new Signature(SignatureTest::CONFIG_FILE_ED25519);
        $headers = array("Foo => Bar");
        $endpoint = "https://localhost/foo";
        $method = "GET";

        $allHeaders = $signature->generateSignatureHeaders($headers, $endpoint, $method);
        var_dump($allHeaders);

        $this->assertArrayNotHasKey("Content-Digest", $allHeaders);
        $this->assertArrayHasKey("x-ebay-signature-key", $allHeaders);
        $this->assertArrayHasKey("Signature-Input", $allHeaders);
        $this->assertArrayHasKey("Signature", $allHeaders);
        $this->assertArrayHasKey("x-ebay-enforce-signature", $allHeaders);

        $this->assertEquals("jwe", $allHeaders["x-ebay-signature-key"]);
        $this->assertStringStartsWith('sig1=("x-ebay-signature-key" "@method" "@path" "@authority");created=', $allHeaders["Signature-Input"]);
        $this->assertStringStartsWith("sig1=:", $allHeaders["Signature"]);
        $this->assertEquals("true", $allHeaders["x-ebay-enforce-signature"]);
    }
}