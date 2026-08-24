<?php

namespace App\Dead;

class DeadCode
{
    public static function unusedMethod()
    {
        return 'never called';
    }

    const UNUSED = 'dead';
}
