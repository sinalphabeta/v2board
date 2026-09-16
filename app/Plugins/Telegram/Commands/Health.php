<?php
namespace App\Plugins\Telegram\Commands;
use App\Models\RiskIndicator;
use App\Models\RiskEvent;
use App\Services\IpInfoService;
use App\Services\RiskService;
class Health extends RiskCommand { public $command='/health'; public $description='检查风险系统健康状态'; public function handle($message,$match=[]){if(!$this->authorized($message))return; $mixed=(new RiskService())->mixedHoneypotNodes(); $asnCount=RiskIndicator::where('type','asn')->where('enabled',1)->count(); $asnAvailable=(new IpInfoService())->asnDatabaseAvailable(); $text='*风险系统状态*\n指标数: '.RiskIndicator::where('enabled',1)->count().'\nASN 指标数: '.$asnCount.'\nASN 数据库: '.($asnAvailable?'可用':'不可用').'\n24h 事件数: '.RiskEvent::where('last_seen_at','>=',time()-86400)->count(); if($mixed)$text.="\n\n⚠️ 混合内鬼节点: ".$this->escapeMarkdown(implode(', ',$mixed)); if($asnCount&&!$asnAvailable)$text.="\n\n⚠️ ASN 数据库不可用"; $this->sendMarkdownReply($message,$text);} }
