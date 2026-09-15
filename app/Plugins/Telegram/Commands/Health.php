<?php
namespace App\Plugins\Telegram\Commands;
use App\Models\RiskIndicator;
use App\Models\RiskEvent;
use App\Services\RiskService;
class Health extends RiskCommand { public $command='/health'; public $description='检查风险系统健康状态'; public function handle($message,$match=[]){if(!$this->authorized($message))return; $mixed=(new RiskService())->mixedHoneypotNodes(); $text='*风险系统状态*\n指标数: '.RiskIndicator::where('enabled',1)->count().'\n24h 事件数: '.RiskEvent::where('last_seen_at','>=',time()-86400)->count(); if($mixed)$text.="\n\n⚠️ 混合内鬼节点: ".$this->escapeMarkdown(implode(', ',$mixed)); $this->sendMarkdown($message->chat_id,$text);} }
