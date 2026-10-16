<?php

namespace App\Services;

use App\Models\ServerV2node;
use App\Utils\Helper;

/**
 * v2node nodes for the node backends that still ask for a node by its protocol (V2bX, XrayR: UniProxy with
 * node_type=vless, trojan…). Every node is a v2node one now and the protocol tables are empty. The node is found by its
 * v2node id and must have that protocol; its config goes out in the format the protocol's own table gave
 * (UniProxyController::config()), filled from the v2node fields. Users, traffic, online users and devices are kept as
 * for the v2node node itself, so the admin panel and the stats see one node.
 *
 * A protocol table that has the id still comes first: UniProxyController asks it before this.
 */
class V2nodeLegacyService
{
    // node_type as the backends send it => the v2node protocol. Not hysteria: Hysteria 1 to V2bX, which v2node lacks
    public const PROTOCOLS = [
        'shadowsocks' => 'shadowsocks',
        'vmess' => 'vmess',
        'v2ray' => 'vmess',
        'vless' => 'vless',
        'trojan' => 'trojan',
        'tuic' => 'tuic',
        'hysteria2' => 'hysteria2',
        'anytls' => 'anytls',
    ];

    public function find($nodeType, $nodeId): ?ServerV2node
    {
        if (!is_string($nodeType) || !isset(self::PROTOCOLS[$nodeType]) || !is_scalar($nodeId)) return null;
        $node = ServerV2node::find($nodeId);
        return $node && $node->protocol === self::PROTOCOLS[$nodeType] ? $node : null;
    }

    /**
     * The config in the format of the node's protocol table: the same keys, in the same order
     */
    public function config(ServerV2node $node): array
    {
        $tls = $node->tls_settings ?? [];
        switch ($node->protocol) {
            case 'shadowsocks':
                // HTTP obfuscation: network http, with its Host and path in network_settings (as the subscriptions read it)
                $http = $node->network === 'http';
                $settings = $node->network_settings ?? [];
                $config = [
                    'server_port' => $node->server_port,
                    'cipher' => $node->cipher,
                    'obfs' => $http ? 'http' : null,
                    'obfs_settings' => $http ? ['path' => $settings['path'] ?? null, 'host' => $settings['Host'] ?? null] : null
                ];
                if ($node->cipher === '2022-blake3-aes-128-gcm') {
                    $config['server_key'] = Helper::getServerKey($node->created_at, 16);
                }
                if ($node->cipher === '2022-blake3-aes-256-gcm') {
                    $config['server_key'] = Helper::getServerKey($node->created_at, 32);
                }
                return $config;
            case 'vmess':
                return [
                    'server_port' => $node->server_port,
                    'network' => $node->network,
                    'networkSettings' => $node->network_settings,
                    'tls' => $node->tls
                ];
            case 'vless':
                return [
                    'server_port' => $node->server_port,
                    'network' => $node->network,
                    'networkSettings' => $node->network_settings,
                    'tls' => $node->tls,
                    'flow' => $node->flow,
                    'tls_settings' => $node->tls_settings,
                    'encryption' => $node->encryption,
                    'encryption_settings' => $node->encryption_settings
                ];
            case 'trojan':
                return [
                    'host' => $node->host,
                    'network' => $node->network,
                    'networkSettings' => $node->network_settings,
                    'server_port' => $node->server_port,
                    'server_name' => $tls['server_name'] ?? null
                ];
            case 'tuic':
                return [
                    'server_port' => $node->server_port,
                    'server_name' => $tls['server_name'] ?? null,
                    'congestion_control' => $node->congestion_control,
                    'zero_rtt_handshake' => $node->zero_rtt_handshake ? true : false
                ];
            case 'hysteria2':
                return [
                    'version' => 2,
                    'host' => $node->host,
                    'server_port' => $node->server_port,
                    'server_name' => $tls['server_name'] ?? null,
                    'up_mbps' => $node->up_mbps,
                    'down_mbps' => $node->down_mbps,
                    'ignore_client_bandwidth' => $node->up_mbps == 0 && $node->down_mbps == 0,
                    'obfs' => $node->obfs,
                    'obfs-password' => $node->obfs_password
                ];
            case 'anytls':
                // The anytls table had no Reality, nor do V2bX's anytls nodes: they would run with TLS, and no client could connect
                if ((int)$node->tls === 2) abort(500, 'anytls with reality is not supported by this node_type, use v2node');
                return [
                    'server_port' => $node->server_port,
                    'server_name' => $tls['server_name'] ?? null,
                    'padding_scheme' => $node->padding_scheme
                ];
        }
        return [];
    }
}
