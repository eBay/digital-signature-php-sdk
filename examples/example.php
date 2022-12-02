<?php

use Ebay\DigitalSignature\Signature;

require 'vendor/autoload.php';

$signature = new Signature("example-config.json");
$endpoint = 'https://api.sandbox.ebay.com/sell/fulfillment/v1/order/14-00032-43825/issue_refund';
const USER_TOKEN = '<token>';
$headers = [
    'Authorization' => 'Bearer ' . USER_TOKEN,
    'Accept' => 'application/json',
    'Content-Type' => 'application/json'
];
$body = '{
    "orderLevelRefundAmount": {
        "currency": "USD",
        "value": 10.39
    },
    "reasonForRefund": "ITEM_NOT_AS_DESCRIBED",
    "comment": "public API test_order_partial_refund"
}';
$headers = $signature->generateSignatureHeaders($headers, "https://api.sandbox.ebay.com/sell/fulfillment/v1/order/14-00032-43825/issue_refund", "POST", $body);

//Making a call
$ch = curl_init($endpoint);
if (!empty($body)) {
    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
}
curl_setopt($ch, CURLOPT_HTTPHEADER, curlifyHeaders($headers));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
curl_close($ch);

echo "response: \n" . $response;

//Header array conversion
function curlifyHeaders($headers): array
{
    $new_headers = [];
    foreach ($headers as $header_name => $header_value) {
        $new_headers[] = $header_name . ': ' . $header_value;
    }

    return $new_headers;
}