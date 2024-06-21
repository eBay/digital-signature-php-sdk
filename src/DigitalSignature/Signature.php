<?php

namespace Ebay\DigitalSignature;

use Mapper\ModelMapper;

class Signature {

    private SignatureConfig $signatureConfig;
    private SignatureService $signatureService;

    public function __construct(string $configPath) {
        $this->loadSignatureConfig($configPath);
        $this->signatureService = new SignatureService();
    }

    /**
     * Returns an array with all required headers. Add this to your HTTP request
     *
     * @param array $headers request headers
     * @param string $endpoint URI of the request
     * @param string $method POST, GET, PUT, etc.
     * @param string|null $body body
     * @return array All headers including the initially transmitted
     */
    public function generateSignatureHeaders(array $headers, string $endpoint, string $method, string $body = null): array {
        $contains_body = !is_null($body);
        if ($contains_body === true) {
            $headers["Content-Digest"] = $this->signatureService->generateContentDigest($body, $this->signatureConfig);
        }
        $timestamp = (string) time();
        $headers["x-ebay-signature-key"] = $this->signatureService->generateSignatureKey($this->signatureConfig);
        $headers["Signature-Input"] = $this->signatureService->generateSignatureInput($contains_body, $timestamp, $this->signatureConfig);
        $headers["Signature"] = $this->signatureService->generateSignature($contains_body, $headers, $method, $endpoint, $timestamp, $this->signatureConfig);

        return $headers;
    }

    /**
     * Load config value into SignatureConfig Object
     *
     * @param string $configPath config path
     */
    private function loadSignatureConfig(string $configPath): void {
        $json = file_get_contents($configPath);
        $jsonDecodedObj = json_decode($json, false);

        $mapper = new ModelMapper();
        $this->signatureConfig = new SignatureConfig();
        $mapper->map($jsonDecodedObj, $this->signatureConfig);

        if (is_null($this->signatureConfig->privateKeyStr) && !is_null($this->signatureConfig->privateKey)) {
            $this->signatureConfig->privateKeyStr = file_get_contents($this->signatureConfig->privateKey);
        }
    }
}