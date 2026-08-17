param([Parameter(Mandatory = $true)][string]$Receipt)
$ErrorActionPreference = "Stop"
python -m ayran.cli release uninstall --receipt $Receipt
