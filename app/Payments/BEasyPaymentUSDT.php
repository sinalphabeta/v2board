<?php

namespace App\Payments;

use \Curl\Curl;

class BEasyPaymentUSDT {
    private $config;

    public function __construct($config)
    {
        $this->config = $config;
    }

    public function form()
    {
        return [
            'bepusdt_url' => [
                'label' => 'API 地址',
                'description' => '您的 BEPUSDT API 接口地址(例如: https://xxx.com)',
                'type' => 'input',
            ],
            'bepusdt_apitoken' => [
                'label' => 'API Token',
                'description' => '您的 BEPUSDT API Token',
                'type' => 'input',
            ],
            'bepusdt_trade_type' => [
                'label' => '交易类型',
                'description' => '您的 BEPUSDT 交易类型，留空时用户可在收银台自行选择',
                'type' => 'input',
            ],
            'bepusdt_currencies' => [
                'label' => '限定币种',
                'description' => '仅在新版收银台模式下生效，留空则不限制；示例：USDT,USDC 或 -BNB,-ETH',
                'type' => 'input',
            ],
        ];
    }

    public function pay($order)
    {
        $tradeType = trim((string) ($this->config['bepusdt_trade_type'] ?? ''));
        $params = [
            'amount' => $order['total_amount'] / 100,
            'notify_url' => $order['notify_url'],
            'order_id' => $order['trade_no'],
            'redirect_url' => $order['return_url']
        ];

        if ($tradeType !== '') {
            $params['trade_type'] = $tradeType;
            $api = '/api/v1/order/create-transaction';
        } else {
            $currencies = trim((string) ($this->config['bepusdt_currencies'] ?? ''));
            if ($currencies !== '') {
                $params['currencies'] = $currencies;
            }
            $api = '/api/v1/order/create-order';
        }

        $params['signature'] = $this->makeSignature($params);

        $curl = new Curl();
        $curl->setUserAgent('BEPUSDT');
        $curl->setOpt(CURLOPT_CONNECTTIMEOUT, 10);
        $curl->setOpt(CURLOPT_TIMEOUT, 30);
        $curl->setOpt(CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
        $curl->post(rtrim($this->config['bepusdt_url'], '/') . $api, json_encode($params));
        $result = $curl->response;
        $error = $curl->error;
        $curl->close();

        if ($error) {
            abort(500, 'Failed to create order. Network error');
        }

        if (!isset($result->status_code) || (int) $result->status_code !== 200) {
            $message = isset($result->message) ? $result->message : 'unknown error';
            abort(500, "Failed to create order. Error: {$message}");
        }

        $paymentURL = $result->data->payment_url ?? null;
        if (empty($paymentURL)) {
            abort(500, 'Failed to create order. Error: payment_url missing');
        }

        return [
            'type' => 1, // 0:qrcode 1:url
            'data' => $paymentURL
        ];
    }

    public function notify($params)
    {
        if (!is_array($params) || empty($params['signature'])) {
            return false;
        }

        $signature = strtolower(trim((string) $params['signature']));
        unset($params['signature']);

        if (!hash_equals($this->makeSignature($params), $signature)) {
            return false;
        }

        // 1: pending 2: success 3: expired
        if (!isset($params['status']) || (int) $params['status'] !== 2) {
            return false;
        }

        if (empty($params['order_id']) || empty($params['trade_id'])) {
            return false;
        }

        return [
            'trade_no' => $params['order_id'],
            'callback_no' => $params['trade_id'],
            'custom_result' => 'ok'
        ];
    }

    private function makeSignature($params)
    {
        foreach ($params as $key => $value) {
            if ($value === '' || $value === null) {
                unset($params[$key]);
            }
        }

        ksort($params);
        $str = stripslashes(urldecode(http_build_query($params))) . $this->config['bepusdt_apitoken'];

        return md5($str);
    }
}
