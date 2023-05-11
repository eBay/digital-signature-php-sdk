<?php

namespace Ebay\DigitalSignature;

use phpseclib3\Crypt\PublicKeyLoader;

class SignatureService {

    /**
     * Generate Content Digest
     *
     * @param string $body request body
     * @param SignatureConfig $signatureConfig signature config
     * @return string content digest
     */
    public function generateContentDigest(string $body, SignatureConfig $signatureConfig): string {
        $cipher = trim(strtolower($signatureConfig->digestAlgorithm));

        return sprintf('%s=:%s:',
            $cipher,
            base64_encode(hash(str_replace('-', '', $cipher), $body, true)));
    }

    /**
     * Generate Signature Key Header
     *
     * @param SignatureConfig $signatureConfig signature config
     * @return string signature key
     */
    public function generateSignatureKey(SignatureConfig $signatureConfig): string {
        return $signatureConfig->jwe;
    }

    /**
     * Generate Signature Input header
     *
     * @param string $timestamp Current time
     * @param SignatureConfig $signatureConfig signature configuration
     * @return string signatureInputHeader
     */
    public function generateSignatureInput(bool $contains_body, string $timestamp, SignatureConfig $signatureConfig): string {
        $signatureParams = $signatureConfig->signatureParams;
        return sprintf('sig1=(%s);created=%s',
            $this->getParamsAsString($contains_body, $signatureParams),
            $timestamp);
    }

    /**
     * Get 'Signature' header value
     *
     * @param array $headers request headers
     * @param string $method POST, GET, PUT, DELETE, etc.
     * @param string $endpoint URL of the requested resource
     * @param string $timestamp current time
     * @param SignatureConfig $signatureConfig signature config
     * @return string signature
     */
    public function generateSignature(bool $contains_body, array $headers, string $method, string $endpoint, string $timestamp, SignatureConfig $signatureConfig): string {
        $signatureBase = $this->calculateBase($contains_body, $headers, $method, $endpoint, $timestamp, $signatureConfig);
        $privateKeyStr = $signatureConfig->privateKeyStr;

        //Signing signature base with private key
        $private = PublicKeyLoader::loadPrivateKey($privateKeyStr);

        //Signing signature base with private key
        $signed = $private->sign($signatureBase);

        //Creating signature from signed base string
        $signature = sprintf('sig1=:%s:', base64_encode($signed));
        return $signature;
    }


    /**
     * Method to calculate base string value
     *
     * @param array $headers request headers
     * @param string $method POST, GET, PUT, DELETE, etc.
     * @param string $endpoint URL of the requested resource
     * @param string $timestamp current time
     * @param SignatureConfig $signatureConfig signature config
     * @return string base string
     */
    private function calculateBase(bool $contains_body, array $headers, string $method, string $endpoint, string $timestamp, SignatureConfig $signatureConfig): string {
        //Signature base is a string that is signed and BASE64 encoded. Each signature param should be enclosed in double quotes.
        //Param and value separated by colon and space. Value is not enclosed.
        //Each param / param value pair needs to be in a separate line, with simple \n linebreak
        $signatureBase = '';
        $signatureParams = $signatureConfig->signatureParams;
        $lowerCaseHeaders = array_change_key_case($headers, CASE_LOWER);

        foreach ($signatureParams as $signatureParam) {
            switch ($signatureParam) {
                case '@method':
                    $signatureBase .= '"@method": ' . $method;
                    break;
                case '@path':
                    $signatureBase .= '"@path": ' . $this->getPath($endpoint);
                    break;
                case '@authority':
                    $signatureBase .= '"@authority": ' . $this->getAuthority($endpoint);
                    break;
                case "@target-uri":
                    $signatureBase .= '"@authority": ' . $endpoint;
                    break;
                case "@scheme":
                    $signatureBase .= '"@scheme": ' . $this->getScheme($endpoint);
                    break;
                case "@query":
                    $signatureBase .= '"@query": ' . $this->getQuery($endpoint);
                    break;
                default:
                    if (array_key_exists($signatureParam, $lowerCaseHeaders)) {
                        $signatureBase .= '"' . $signatureParam . '": ' . $lowerCaseHeaders[$signatureParam];
                    } else {
                        continue 2; // skip the new line
                    }
            }
            //Adding a linebreak between params
            $signatureBase .= "\n";
        }
        //Signature params pseudo header and timestamp are formatted differently that previous ones
        $signatureBase .= sprintf('"@signature-params": (%s);created=%s', $this->getParamsAsString($contains_body, $signatureParams), $timestamp);

        return $signatureBase;
    }

    //Getting authority from an API call endpoint
    private function getAuthority($endpoint): string
    {
        $urlParsed = parse_url($endpoint);
        $result = $urlParsed['host'];

        if (array_key_exists('scheme', $urlParsed) &&
            array_key_exists('port', $urlParsed)) {

            $scheme = $urlParsed['scheme'];
            $port = $urlParsed['port'];
            
            if ($scheme == "https" && $port != 443
                || $scheme == "http" && $port != 80) {
                $result .= ":" . $port;
            }
        }

        return $result;
    }

    //Getting path from an API call endpoint
    private function getPath($endpoint): string {
        return parse_url($endpoint)['path'];
    }

    private function getScheme($endpoint): string {
        return parse_url($endpoint)['scheme'];
    }

    private function getQuery($endpoint): string {
        return parse_url($endpoint)['query'];
    }

    //Getting params as string
    private function getParamsAsString(bool $contains_body, array $signature_params): string {
        //Params need to be enclosed in double quotes and separated with space
        if ($contains_body === true) {
            return '"' . implode('" "', $signature_params) . '"';
        } else {
            return '"' . implode('" "', array_filter($signature_params, function($element) {
                return strtolower($element) !== "content-digest";
            })) . '"';
        }
    }
}