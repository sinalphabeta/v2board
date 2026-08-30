<?php

namespace App\Protocols;

use App\Utils\Helper;

class Shadowrocket
{
    public $flag = 'shadowrocket';
    private $servers;
    private $user;

    public function __construct($user, $servers)
    {
        $this->user = $user;
        $this->servers = $servers;
    }

    public function handle()
    {
        $user = $this->user;

        $uri = '';
        //display remaining traffic and expire date
        // $upload = round($user['u'] / (1024*1024*1024), 2);
        // $download = round($user['d'] / (1024*1024*1024), 2);
        // $usedTraffic = round(($user['u'] + $user['d']) / (1024*1024*1024), 2);
        // $totalTraffic = round($user['transfer_enable'] / (1024*1024*1024), 2);
        // $expiredDate = date('Y-m-d', $user['expired_at']);
        // $uri .= "STATUS=🚀流量:{$usedTraffic}GB/{$totalTraffic}GB💡到期:{$expiredDate},点↻刷新→\r\n";

        
        // --- 1. 流量计算与表情判断 ---
        // 计算数值 (GB) 用于显示
        $usedTraffic = round(($user['u'] + $user['d']) / (1024*1024*1024), 2);
        $totalTraffic = round($user['transfer_enable'] / (1024*1024*1024), 2);
        
        // 计算百分比
        $percentage = 0;
        if ($user['transfer_enable'] > 0) {
            $percentage = (($user['u'] + $user['d']) / $user['transfer_enable']) * 100;
        }

        // 根据百分比设定流量表情
        $trafficEmoji = '🥳'; // 默认 (<=80%)
        if ($percentage > 95) {
            $trafficEmoji = '😣'; // >95%
        } elseif ($percentage > 80) {
            $trafficEmoji = '😢'; // 80% - 95%
        }

        // --- 2. 到期时间判断 ---
        $expireEmoji = '💡'; // 默认表情
        $expiredDateStr = '';

        if (is_null($user['expired_at'])) {
            // 如果是 NULL，显示长期有效
            $expiredDateStr = '长期有效';
        } else {
            // 格式化日期
            $expiredDateStr = date('Y-m-d', $user['expired_at']);
            
            // 检查是否剩余少于 48 小时 (48 * 3600 = 172800 秒)
            // 且必须是尚未过期的情况 ( > time() )
            if (($user['expired_at'] - time()) < 172800 && ($user['expired_at'] > time())) {
                $expireEmoji = '‼️';
            }
        }

        // --- 3. 拼接最终字符串 ---
        $uri .= "STATUS={$trafficEmoji}流量:{$usedTraffic}GB/{$totalTraffic}GB{$expireEmoji}到期:{$expiredDateStr},点↻刷新→\r\n";

        foreach ($this->servers as $server) {
            if ($server['type'] === 'vmess' || ($server['type'] === 'v2node' && $server['protocol'] === 'vmess')) {
                $uri .= self::buildVmess($user['uuid'], $server);
            } else {
                $uri .= Helper::buildUri($this->user['uuid'], $server);
            }
        }
        return base64_encode($uri);
    }

    public static function buildVmess($uuid, $server)
    {
        $userinfo = base64_encode('auto:' . $uuid . '@' . $server['host'] . ':' . $server['port']);
        $config = [
            'tfo' => 1,
            'remark' => $server['name'],
            'alterId' => 0
        ];
        if ($server['tls']) {
            $config['tls'] = 1;
            $tlsSettings = $server['tls_settings'] ?? ($server['tlsSettings'] ?? []);
            $config['allowInsecure'] = (int)($tlsSettings['allow_insecure'] ?? $tlsSettings['allowInsecure'] ?? 0);
            $config['peer'] = $tlsSettings['server_name'] ?? $tlsSettings['serverName'] ?? '';
        }
        if ($server['network'] === 'tcp') {
            $tcpSettings = $server['network_settings'] ?? ($server['networkSettings'] ?? []);
            if (isset($tcpSettings['header']['type']) && !empty($tcpSettings['header']['type']))
                $config['obfs'] = $tcpSettings['header']['type'];
            if (isset($tcpSettings['header']['request']['path'][0]) && !empty($tcpSettings['header']['request']['path'][0]))
                $config['path'] = $tcpSettings['header']['request']['path'][0];
            if (isset($tcpSettings['header']['request']['headers']['Host'][0]))
                $config['obfsParam'] = $tcpSettings['header']['request']['headers']['Host'][0];
        }
        if ($server['network'] === 'ws') {
            $config['obfs'] = "websocket";
            $wsSettings = $server['network_settings'] ?? ($server['networkSettings'] ?? []);
            if (isset($wsSettings['path']) && !empty($wsSettings['path']))
                $config['path'] = $wsSettings['path'];
            if (isset($wsSettings['headers']['Host']) && !empty($wsSettings['headers']['Host']))
                $config['obfsParam'] = $wsSettings['headers']['Host'];
            if (isset($wsSettings['security']))
                $config['method'] = $wsSettings['security'];
        }
        if ($server['network'] === 'grpc') {
            $config['obfs'] = "grpc";
            $grpcSettings = $server['network_settings'] ?? ($server['networkSettings'] ?? []);
            if (isset($grpcSettings['serviceName']) && !empty($grpcSettings['serviceName']))
                $config['path'] = $grpcSettings['serviceName'];
            if (isset($tlsSettings)) {
                $config['host'] = $tlsSettings['server_name'] ?? $tlsSettings['serverName'] ?? '';
            } else {
                $config['host'] = $server['host'];
            }
        }
        $query = http_build_query($config, '', '&', PHP_QUERY_RFC3986);
        $uri = "vmess://{$userinfo}?{$query}";
        $uri .= "\r\n";
        return $uri;
    }

}
