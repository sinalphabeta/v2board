<?php

namespace App\Http\Controllers\V1\Guest;

use App\Http\Controllers\Controller;
use App\Plugins\RiskTelegram\RiskBot;
use App\Services\RiskSettings;
use Illuminate\Http\Request;

class RiskTelegramController extends Controller
{
    public function webhook(Request $request)
    {
        $token = (string)RiskSettings::get('bot_token');
        $headerSecret = (string)$request->header('X-Telegram-Bot-Api-Secret-Token', '');
        $validHeader = $token && $headerSecret && hash_equals(hash('sha256', $token), $headerSecret);
        if (!$validHeader) abort(401);
        $callback = $request->input('callback_query');
        $message = $request->input('message');
        if (is_array($callback)) {
            (new RiskBot())->handleCallback($callback);
        } elseif (is_array($message) && !empty($message['text']) && isset($message['chat']['id'])) {
            (new RiskBot())->handleMessage($message);
        }
    }
}
