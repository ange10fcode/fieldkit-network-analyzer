param([Parameter(Mandatory=$true)][string]$JsonJar)
$ErrorActionPreference = 'Stop'
$JsonJar=(Resolve-Path -LiteralPath $JsonJar).Path
$testBuild=Join-Path $PSScriptRoot 'build\tests'
New-Item -ItemType Directory -Force -Path $testBuild | Out-Null
$sourceDir=Join-Path $PSScriptRoot 'app\src\main\java\com\fieldkit\analyzer'
$sourceFiles=@('Ip.java','DnsClient.java','NetworkTools.java','Report.java','Task.java','LanSelection.java','NetworkInventoryLogic.java','LanServiceMerge.java','NearbySignal.java','NearbySnapshot.java','SnapshotDocument.java','DeviceFacts.java','LanNameDiscovery.java','SsdpNames.java','UwbPairing.java','PrecisionReading.java') | ForEach-Object { Join-Path $sourceDir $_ }
$testFiles=@(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'tests') -Filter '*.java')
$sourceFiles += @($testFiles | ForEach-Object FullName)
& javac --release 8 -encoding UTF-8 -cp $JsonJar -d $testBuild @sourceFiles
if($LASTEXITCODE -ne 0){throw 'Test compilation failed.'}
foreach($test in $testFiles){
    & java -cp "$JsonJar;$testBuild" "com.fieldkit.analyzer.$($test.BaseName)"
    if($LASTEXITCODE -ne 0){throw "$($test.BaseName) failed."}
}
