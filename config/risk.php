<?php

return [
    'api_key_hash' => env('RISK_API_KEY_HASH', ''),
    'alert_chat_id' => env('RISK_ALERT_CHAT_ID', ''),
    'bot_token' => env('RISK_BOT_TOKEN', ''),
    'honeypot_group_id' => env('RISK_HONEYPOT_GROUP_ID', 0),
    'ip_info_enabled' => env('RISK_IP_INFO_ENABLED', true),
    'ip_database_v4' => storage_path('app/ip2region/ip2region_v4.xdb'),
    'ip_database_v6' => storage_path('app/ip2region/ip2region_v6.xdb'),
    'ip_database_urls' => [
        'v4' => 'https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb',
        'v6' => 'https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb',
    ],
    'trusted_proxies' => env('TRUSTED_PROXIES', ''),
];
