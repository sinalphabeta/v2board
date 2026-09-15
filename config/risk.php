<?php

return [
    'api_key_hash' => env('RISK_API_KEY_HASH', ''),
    'alert_chat_id' => env('RISK_ALERT_CHAT_ID', ''),
    'bot_token' => env('RISK_BOT_TOKEN', ''),
    'honeypot_group_id' => env('RISK_HONEYPOT_GROUP_ID', 0),
    'trusted_proxies' => env('TRUSTED_PROXIES', ''),
];
