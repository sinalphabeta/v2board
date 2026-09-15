<?php
namespace App\Plugins\Telegram\Commands;
use App\Models\RiskIndicator;
use App\Services\RiskService;
class Edit extends RiskCommand { public $command='/edit'; public $description='编辑风险名单备注'; public function handle($message,$match=[]){if(!$this->authorized($message))return; $i=RiskIndicator::find($message->args[0]??0); if(!$i){$this->telegramService->sendMessage($message->chat_id,'not found');return;} $i->note=implode(' ',array_slice($message->args,1)); $i->save(); (new RiskService())->audit('edit',$i,$this->actorId); $this->telegramService->sendMessage($message->chat_id,'updated');} }
