function Process-Order {
    param([string[]]$Items)
    if (-not $Items) {
        $total = $null
    } else {
        $total = $Items.Count * 10
    }
    $total.ToString()
}

function Helper {
    $multiplier = 2
    $x = $multiplier
}

Helper
$result = Process-Order -Items @()
Write-Output $result
