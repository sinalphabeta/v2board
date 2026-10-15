<?php

return [
    // Fallbacks: these six are edited on the admin panel's 风控概览 page (App\Services\RiskSettings);
    // once saved there, the saved values win and the .env lines can be removed.
    'alert_chat_id' => env('RISK_ALERT_CHAT_ID', ''),
    'bot_token' => env('RISK_BOT_TOKEN', ''),
    'honeypot_group_id' => env('RISK_HONEYPOT_GROUP_ID', 0),
    'ip_info_enabled' => env('RISK_IP_INFO_ENABLED', true),
    'asn_cache_ttl' => env('RISK_ASN_CACHE_TTL', 3600),
    'trusted_proxies' => env('TRUSTED_PROXIES', ''),
    'geoip_directory' => storage_path('app/risk-geoip'),
    'geoip_databases' => [
        'qqwry' => storage_path('app/risk-geoip/qqwry.ipdb'),
        'city' => storage_path('app/risk-geoip/dbip-city-lite.mmdb'),
        'asn' => storage_path('app/risk-geoip/dbip-asn-lite.mmdb'),
    ],
    'geoip_manifest' => storage_path('app/risk-geoip/manifest.json'),
    'geoip_npm_metadata_url' => 'https://registry.npmjs.org/qqwry.ipdb/latest',
    'geoip_dbip_url' => 'https://download.db-ip.com/free/dbip-%s-lite-%s.mmdb.gz',
];
