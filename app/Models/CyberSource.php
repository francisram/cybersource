<?php

namespace App\Models;

use DateTime;
use DateTimeZone;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Http;

class CyberSource extends Model
{
    protected $merchantId;
    protected $merchantKeyId;
    protected $merchantSecretKey;
    protected $requestHost;
    public function __construct()
    {
        $this->merchantId = 'bepsa_sandbox';
        $this->merchantKeyId = 'cf9e252d-2431-43a9-88ac-76999a374d3e';
        //$this->merchantSecretKey = base64_decode('1xwdEX2yJ5reDO/7Ja8fRbb3Ri5YhprtuP7l7bNEtLM=', true); // Decode the secret key
        $this->merchantSecretKey = '1xwdEX2yJ5reDO/7Ja8fRbb3Ri5YhprtuP7l7bNEtLM='; // Decode the secret key
        $this->requestHost = 'apitest.cybersource.com';}
    public function createPaymentContext()
    {
        $body = json_encode($this->buildRequestBody());
        $date = (new DateTime('now', new DateTimeZone('GMT')))->format('D, d M Y H:i:s \G\M\T');
        $digest = base64_encode(hash('sha256', $body, true));
        $signature = $this->generateSignature($body, $date, 'SHA-256=' . $digest);

        $headers = ['v-c-merchant-id' => $this->merchantId,
            'Date' => $date,
            'Host' => $this->requestHost,
            'Digest' => 'SHA-256=' . $digest,
            'Signature' => $signature,
            'Content-Type' => 'application/json',
        ];

        /*
        $headers = '{
        "v-c-merchant-id": "' . $this->merchantId . '",
        "Date": "' . $date . '",
        "Host": "' . $this->requestHost . '",
        "Digest": "SHA-256=' . $digest . '",
        "Signature": "' . $signature . '",
        "Content-Type": "application/json"
        }';

         */
        $response = Http::withHeaders($headers)->post('https://' . $this->requestHost . '/up/v1/capture-contexts', $body);
        return $response->json();
    }
    protected function generateSignature($body, $date, $digest)
    {
        $signingString = "host: {$this->requestHost}\n
                        date: {$date}\n(request-target): post /up/v1/capture-contexts\n
                        digest: {$digest}\n
                        v-c-merchant-id: {$this->merchantId}";
        $signature = base64_encode(hash_hmac('sha256', $signingString, $this->merchantSecretKey, true));
        return 'keyid="' . $this->merchantKeyId . '", algorithm="HmacSHA256", headers="host date (request-target) digest v-c-merchant-id", signature="' . $signature . '"';}
    protected function buildRequestBody()
    {
        return [

            "targetOrigins" => [
                "https://sighotest.180softlab.com",
            ], "clientVersion" => "0.15",
            "allowedCardNetworks" => ["VISA",
                "MASTERCARD",
            ],
            "allowedPaymentTypes" => ["PANENTRY", "SRC"],
            "country" => "US",
            "locale" => "en_US",
            "captureMandate" => [
                "billingType" => "FULL",
                "requestEmail" => false,
                "requestPhone" => false,
                "requestShipping" => false,
                "shipToCountries" => ["US", "GB"],
                "showAcceptedNetworkIcons" => true,
            ],
            "orderInformation" => ["amountDetails" =>
                [
                    "totalAmount" => "21.00",
                    "currency" => "USD",
                ],
            ],

        ];
    }
}
