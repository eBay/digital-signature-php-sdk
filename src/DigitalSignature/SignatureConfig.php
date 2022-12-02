<?php

namespace Ebay\DigitalSignature;

class SignatureConfig
{
    /**
     * @required
     * @var string
     */
    public $digestAlgorithm;

    /**
     * @required
     * @var string
     */
    public $algorithm;

    /**
     * @var string
     */
    public $privateKey;

    /**
     * @var string
     */
    public $privateKeyStr;

    /**
     * @required
     * @var string
     */
    public $jwe;

    /**
     * @required
     * @var array
     */
    public $signatureParams;
}