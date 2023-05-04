rule yaraBinaryProc
{
    meta:
    desc = "First test File"
    weight = 10
    strings:
    $a = {59 61 72 61 20 50 72 6F 63}
    $b = {31 32 37 2E 30 2E 30 2E 31}
    condition:
    $a or $b
}