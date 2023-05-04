rule yaraBasicTestCase
{
    meta:
    desc = "This checks for a local IP address and a string that says Yara Proc in ASCII and Hex"
    weight = 10
    strings:
    $a = "Yara Proc"
    $b = "127.0.0.1"
    condition:
    $a or $b
}