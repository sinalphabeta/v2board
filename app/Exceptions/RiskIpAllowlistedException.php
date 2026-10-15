<?php

namespace App\Exceptions;

use App\Models\RiskIndicator;

/**
 * An IP indicator was not added, enabled or changed because an enabled IP allowlist entry covers it.
 */
class RiskIpAllowlistedException extends \RuntimeException
{
    public $value;
    public $entry;

    public function __construct(string $value, RiskIndicator $entry)
    {
        parent::__construct("{$value} is covered by the IP allowlist entry {$entry->value}");
        $this->value = $value;
        $this->entry = $entry;
    }
}
