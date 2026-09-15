<?php

return [
    'api_key_hash' => env('RISK_API_KEY_HASH', ''),
    'alert_chat_id' => env('RISK_ALERT_CHAT_ID', ''),
    'bot_token' => env('RISK_BOT_TOKEN', ''),
    'honeypot_group_id' => env('RISK_HONEYPOT_GROUP_ID', 0),
    'ip_info_enabled' => env('RISK_IP_INFO_ENABLED', true),
    'geoip_directory' => storage_path('app/risk-geoip'),
    'geoip_databases' => [
        'qqwry' => storage_path('app/risk-geoip/qqwry.ipdb'),
        'city' => storage_path('app/risk-geoip/dbip-city-lite.mmdb'),
        'asn' => storage_path('app/risk-geoip/dbip-asn-lite.mmdb'),
    ],
    'geoip_manifest' => storage_path('app/risk-geoip/manifest.json'),
    'geoip_npm_metadata_url' => 'https://registry.npmjs.org/qqwry.ipdb/latest',
    'geoip_dbip_url' => 'https://download.db-ip.com/free/dbip-%s-lite-%s.mmdb.gz',
    'trusted_proxies' => env('TRUSTED_PROXIES', ''),
];
