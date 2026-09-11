# End-to-end verification of the GhidraMCP12 bridge against a real Ghidra session.
#
# Assumes a bridge is already listening (see tools/e2e.ps1, which starts the
# headless server and then runs this). It exercises every endpoint in two passes:
#
#   1. a generic sweep of every registered endpoint - read endpoints must return
#      HTTP 200, and endpoints that need parameters must fail with a 4xx and a
#      useful message rather than a 500 or an empty body;
#   2. a scripted walkthrough that checks the *content* of the important
#      responses and performs every mutating operation, verifying each change by
#      reading it back.
#
#   powershell -File tools/test_endpoints.ps1
#
[CmdletBinding()]
param(
    [string]$BaseUrl = "http://127.0.0.1:8192",
    # Kept outside the project tree: the report is a test artifact, and writing it
    # into dist/ would put it in the same folder as the shippable extension zip.
    [string]$ReportFile = (Join-Path $env:TEMP "ghidramcp12-e2e-report.txt")
)

$ErrorActionPreference = "Continue"
$script:pass = 0
$script:fail = 0
$script:warn = 0
$script:lines = New-Object System.Collections.Generic.List[string]

function Say($msg, $color = "Gray") {
    Write-Host $msg -ForegroundColor $color
    $script:lines.Add($msg)
}

function Ok($name, $detail = "") {
    $script:pass++
    Say ("  PASS  " + $name + $(if ($detail) { "  -> $detail" } else { "" })) "Green"
}

function Bad($name, $detail = "") {
    $script:fail++
    Say ("  FAIL  " + $name + $(if ($detail) { "  -> $detail" } else { "" })) "Red"
}

function Warn($name, $detail = "") {
    $script:warn++
    Say ("  WARN  " + $name + $(if ($detail) { "  -> $detail" } else { "" })) "Yellow"
}

# HTTP via curl rather than Invoke-WebRequest: PowerShell's client never gives
# back the body of a non-2xx response (and its Chinese localised error text hides
# the real status), while this suite is specifically about checking error bodies.
$script:marker = "<<<HTTP_STATUS:"

function Invoke-Bridge([string]$path, [hashtable]$query, [hashtable]$form, [string]$method) {
    $uri = $BaseUrl + $path
    if ($query -and $query.Count -gt 0) {
        $pairs = @()
        foreach ($k in $query.Keys) {
            if ($null -ne $query[$k] -and "$($query[$k])" -ne "") {
                $pairs += "$k=" + [uri]::EscapeDataString("$($query[$k])")
            }
        }
        if ($pairs.Count -gt 0) { $uri += "?" + ($pairs -join "&") }
    }

    $curlArgs = @("-s", "-m", "180", "-w", "$($script:marker)%{http_code}", "-X", $method)
    $bodyFile = $null
    if ($form -and $form.Count -gt 0) {
        # A JSON body, not form encoding: this is what MCP clients send, and it
        # sidesteps every shell/URL-encoding hazard for values containing spaces,
        # quotes or newlines. Writing the body to a file keeps PowerShell from
        # touching the bytes at all.
        $payload = @{}
        foreach ($k in $form.Keys) {
            if ($null -ne $form[$k]) { $payload[$k] = $form[$k] }
        }
        $json = $payload | ConvertTo-Json -Compress -Depth 10
        $bodyFile = Join-Path $env:TEMP ("ghidramcp-e2e-" + [guid]::NewGuid().ToString("N") + ".json")
        [System.IO.File]::WriteAllText($bodyFile, $json, (New-Object System.Text.UTF8Encoding($false)))
        $curlArgs += @("--data-binary", "@$bodyFile", "-H", "Content-Type: application/json")
    }
    $curlArgs += $uri

    try {
        $raw = & curl.exe @curlArgs 2>$null
    }
    finally {
        if ($bodyFile -and (Test-Path $bodyFile)) { Remove-Item $bodyFile -Force -ErrorAction SilentlyContinue }
    }
    $text = ($raw | Out-String)
    $status = 0
    $idx = $text.LastIndexOf($script:marker)
    if ($idx -ge 0) {
        $statusText = $text.Substring($idx + $script:marker.Length).Trim()
        $text = $text.Substring(0, $idx)
        [int]::TryParse($statusText, [ref]$status) | Out-Null
    }
    $text = $text.TrimEnd("`r", "`n")
    return @{ ok = ($status -ge 200 -and $status -lt 300); status = $status; body = $text }
}

function Get-Json([string]$path, [hashtable]$query) {
    return Invoke-Bridge -path $path -query $query -method "GET"
}

function Post-Json([string]$path, [hashtable]$form) {
    return Invoke-Bridge -path $path -form $form -method "POST"
}

function As-Object($text) {
    try { return $text | ConvertFrom-Json } catch { return $null }
}

function Check([string]$name, [scriptblock]$body) {
    try {
        $result = & $body
        if ($result -eq $true) { Ok $name } else { Bad $name "$result" }
    }
    catch {
        Bad $name "exception: $($_.Exception.Message)"
    }
}

# --------------------------------------------------------------------- preamble
Say ""
Say "=== GhidraMCP12 end-to-end verification ===" "Cyan"
Say "bridge : $BaseUrl"
Say "time   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

$health = Get-Json "/_health" @{}
if (-not $health.ok) {
    Bad "bridge reachable" "no answer from $BaseUrl/_health - $($health.body)"
    Say "Aborting: the bridge is not running." "Red"
    exit 1
}
Ok "bridge reachable" "HTTP $($health.status)"
$healthObj = As-Object $health.body
Say "health : $($health.body)"

# ------------------------------------------------------- 1. generic endpoint sweep
Say ""
Say "--- pass 1: generic endpoint sweep ---" "Cyan"
$tools = Get-Json "/_tools" @{}
$toolsObj = As-Object $tools.body
$allEndpoints = @()
foreach ($cat in $toolsObj.categories.PSObject.Properties) {
    foreach ($e in $cat.Value) { $allEndpoints += $e }
}
Say "registered endpoints: $($allEndpoints.Count) across $(@($toolsObj.categories.PSObject.Properties).Count) categories"

# Paths whose parameters live in the path itself and are exercised in pass 2.
$scriptedInPass2 = @("/functions/{address}")
$getEndpoints = $allEndpoints | Where-Object { $_.method -eq "GET" } |
    Where-Object { $_.path -notmatch '\{' } | Sort-Object path -Unique
Say "GET endpoints without path parameters: $($getEndpoints.Count)"

$sweep5xx = @()
$sweepEmpty = @()
foreach ($e in $getEndpoints) {
    $r = Get-Json $e.path @{}
    if ($r.status -ge 500) {
        $sweep5xx += "$($e.path) -> HTTP $($r.status): $($r.body)"
        continue
    }
    if ($r.ok -and [string]::IsNullOrWhiteSpace($r.body)) {
        $sweepEmpty += "$($e.path) -> 200 with an empty body"
    }
    if ($r.status -eq 404 -and $r.body -notmatch '^\{') {
        $sweep5xx += "$($e.path) -> non-JSON 404 body: $($r.body)"
    }
}

if ($sweep5xx.Count -eq 0) {
    Ok "no endpoint returned 5xx or a malformed error body"
}
else {
    foreach ($s in $sweep5xx) { Bad "endpoint sweep" $s }
}
if ($sweepEmpty.Count -eq 0) {
    Ok "no endpoint returned an empty 200 body"
}
else {
    foreach ($s in $sweepEmpty) { Warn "empty response" $s }
}

# Endpoints that legitimately need parameters must report that clearly.
$needsParams = @("/functions/pcode", "/functions/callers", "/functions/callees",
    "/functions/basic-blocks", "/variables", "/decompile", "/disassemble",
    "/types/detail", "/scripts/source", "/memory/read", "/data/read",
    "/functions/by-address", "/xrefs/to", "/xrefs/from")
foreach ($p in $needsParams) {
    $r = Get-Json $p @{}
    if ($r.status -eq 400 -or $r.status -eq 404 -or $r.status -eq 409) {
        $obj = As-Object $r.body
        if ($obj -and $obj.error) { Ok "missing-parameter error is clear: $p" "$($obj.error)" }
        else { Warn "missing-parameter error body: $p" $r.body }
    }
    elseif ($r.status -ge 500) {
        Bad "missing-parameter handling: $p" "HTTP $($r.status): $($r.body)"
    }
    else {
        Warn "expected a 4xx for $p without parameters" "got HTTP $($r.status)"
    }
}

# --------------------------------------------- 2. content checks and a full workflow
Say ""
Say "--- pass 2: content checks ---" "Cyan"

$info = As-Object (Get-Json "/program/info" @{}).body
Check "program/info returns the loaded program" {
    if ($info.name -eq "version.dll") { $true } else { "name=$($info.name)" }
}
Check "program/info reports the PE language" {
    if ("$($info.languageId)" -like "x86:LE:64*") { $true } else { "languageId=$($info.languageId)" }
}
Say "  program: $($info.name)  $($info.format)  $($info.languageId)"

$summary = As-Object (Get-Json "/program/summary" @{}).body
Check "program/summary counts functions" {
    if ([int]$summary.functions -gt 0) { $true } else { "functions=$($summary.functions)" }
}
Say "  functions=$($summary.functions) symbols=$($summary.symbols) strings=$($summary.strings) dataTypes=$($summary.dataTypes)"

$blocks = As-Object (Get-Json "/memory/blocks" @{}).body
Check "memory/blocks lists at least .text" {
    $names = ($blocks.items | ForEach-Object { $_.name }) -join ","
    if ($names -match "\.text") { $true } else { "blocks=$names" }
}

$exports = As-Object (Get-Json "/exports" @{ limit = 2000 }).body
Check "exports are present and addressable" {
    if ([int]$exports.count -gt 0) { $true } else { "count=$($exports.count)" }
}
$firstExport = $exports.items | Select-Object -First 1
if ($firstExport) { Say "  first export: $($firstExport.name) @ $($firstExport.address)" }

$funcs = As-Object (Get-Json "/functions" @{ limit = 5000 }).body
Check "functions list is non-empty" {
    if ([int]$funcs.count -gt 0) { $true } else { "count=$($funcs.count)" }
}
Say "  functions listed: $($funcs.count)"

# Pick a function that actually has a body worth decompiling.
$target = $funcs.items | Where-Object { $_.bodySize -gt 16 -and -not $_.isExternal } |
    Select-Object -First 1
if (-not $target) { $target = $funcs.items | Select-Object -First 1 }
Say "  decompile target: $($target.name) @ $($target.address) (bodySize=$($target.bodySize))"

$dec = As-Object (Post-Json "/decompile" @{ address = $target.address; timeout = 120 }).body
Check "decompile returns C code" {
    if ($dec.decompiled -and $dec.decompiled.Length -gt 20) {
        $true
    } else { "decompiled=$($dec.decompiled); error=$($dec.error)" }
}
if ($dec.decompiled) {
    $firstCodeLine = ($dec.decompiled -split "`n" | Where-Object { $_.Trim() } | Select-Object -First 3) -join " | "
    Say "  decompiled head: $firstCodeLine"
}

$dis = As-Object (Post-Json "/disassemble" @{ address = $target.address; bytes = "true" }).body
Check "disassemble returns instructions" {
    if ([int]$dis.instructionCount -gt 0) { $true } else { "instructionCount=$($dis.instructionCount)" }
}
Check "disassemble includes raw bytes" {
    if ($dis.instructions -and $dis.instructions.Count -gt 0 -and $dis.instructions[0].bytes) { $true }
    else { "no bytes field on the first instruction" }
}
Say "  instructions: $($dis.instructionCount), first: $($dis.instructions[0].instruction)"

$fdet = As-Object (Get-Json "/functions/$($target.address)" @{}).body
Check "function detail (path form) includes parameters" {
    if ($null -ne $fdet.parameters) { $true } else { "parameters missing" }
}
Check "function detail includes callers and callees" {
    if ($null -ne $fdet.callers -and $null -ne $fdet.callees) { $true } else { "callers/callees missing" }
}
$fdet2 = As-Object (Get-Json "/functions/by-address" @{ address = $target.address }).body
Check "function detail (by-address form) includes callers and callees" {
    if ($null -ne $fdet2.callers -and $null -ne $fdet2.callees) { $true } else { "callers/callees missing" }
}

$xr = As-Object (Get-Json "/xrefs/to" @{ address = $target.address; limit = 50 }).body
Check "xrefs/to answers for a function entry" {
    if ($null -ne $xr.count) { $true } else { "no count field" }
}
Say "  xrefs to $($target.name): $($xr.count)"

$strings = As-Object (Get-Json "/strings" @{ limit = 5000 }).body
Check "strings are found in the PE" {
    if ([int]$strings.count -gt 0) { $true } else { "count=$($strings.count)" }
}
Say "  strings: $($strings.count)"
if ($strings.items.Count -gt 0) {
    $sample = $strings.items | Select-Object -First 3 | ForEach-Object { $_.value }
    Say "  sample: $($sample -join ' / ')"
}

$types = As-Object (Get-Json "/types" @{ limit = 5000 }).body
Check "data types are enumerable" {
    if ([int]$types.count -gt 0) { $true } else { "count=$($types.count)" }
}
Say "  data types: $($types.count)"

$dtypes = As-Object (Get-Json "/data/read" @{ address = $info.imageBase; type = "byte" }).body
Check "data/read reads a typed value" {
    if ($null -ne $dtypes.value) { $true } else { "no value" }
}

$mem = As-Object (Get-Json "/memory/read" @{ address = $info.imageBase; length = 32 }).body
Check "memory/read returns hex and ascii" {
    if ($mem.hex -and $mem.ascii) { $true } else { "hex/ascii missing" }
}
Say "  bytes at imageBase: $($mem.hex)"

$pcode = As-Object (Get-Json "/functions/pcode" @{ address = $target.address }).body
Check "pcode returns operations" {
    if ([int]$pcode.operationCount -gt 0) { $true } else { "operationCount=$($pcode.operationCount); error=$($pcode.error)" }
}

$blocks2 = As-Object (Get-Json "/functions/basic-blocks" @{ address = $target.address }).body
Check "basic blocks are reported" {
    if ([int]$blocks2.blockCount -gt 0) { $true } else { "blockCount=$($blocks2.blockCount)" }
}

$cg = As-Object (Get-Json "/functions/callgraph" @{ address = $target.address; depth = 2 }).body
Check "call graph returns nodes and edges" {
    if ($cg.nodes -and $cg.nodes.Count -gt 0) { $true } else { "no nodes" }
}

$scripts = As-Object (Get-Json "/scripts" @{}).body
Check "scripts are discoverable" {
    if ([int]$scripts.count -gt 0) { $true } else { "count=$($scripts.count)" }
}
Say "  scripts found: $($scripts.count)"

# ------------------------------------------------------------- 3. mutating workflow
Say ""
Say "--- pass 3: mutating workflow ---" "Cyan"

# A struct, then a type applied to data, then a rename, comment, symbol and bookmark.
$struct = Post-Json "/types/struct/create" @{ name = "McpE2EStruct"; fields = "int count, char *name, char buf[16]" }
$structObj = As-Object $struct.body
Check "create a struct data type" {
    if ($struct.ok -and $structObj.members -and $structObj.members.Count -eq 3) { $true }
    else { "HTTP $($struct.status): $($struct.body)" }
}
if ($structObj.members) {
    Say "  McpE2EStruct size=$($structObj.size) members=$(($structObj.members | ForEach-Object { "$($_.name):$($_.dataType)@$($_.offset)" }) -join ', ')"
}

$detail = As-Object (Get-Json "/types/detail" @{ name = "McpE2EStruct" }).body
Check "read the struct layout back" {
    if ($detail.members.Count -eq 3) { $true } else { "members=$($detail.members.Count)" }
}

$enum = Post-Json "/types/enum/create" @{ name = "McpE2EEnum"; values = "MCP_A=1,MCP_B=2,MCP_C=4" }
$enumObj = As-Object $enum.body
Check "create an enum data type" {
    if ($enum.ok -and $enumObj.name -eq "McpE2EEnum") { $true } else { "HTTP $($enum.status): $($enum.body)" }
}

$rename = Post-Json "/functions/rename" @{ address = $target.address; newName = "mcp_renamed_function" }
Check "rename a function by address" {
    if ($rename.ok -and (As-Object $rename.body).name -eq "mcp_renamed_function") { $true }
    else { "HTTP $($rename.status): $($rename.body)" }
}
$back = As-Object (Get-Json "/functions/by-address" @{ address = $target.address }).body
Check "the rename is visible on the next read" {
    if ($back.name -eq "mcp_renamed_function") { $true } else { "name=$($back.name)" }
}

$proto = Post-Json "/functions/set-prototype" @{ address = $target.address;
    prototype = "int __cdecl mcp_renamed_function(int a, char *b)" }
Check "apply a C prototype with an explicit calling convention" {
    if ($proto.ok) { $true } else { "HTTP $($proto.status): $($proto.body)" }
}
$protoPlain = Post-Json "/functions/set-prototype" @{ address = $target.address;
    prototype = "int mcp_renamed_function(int mcpParamA, char *mcpParamB)" }
Check "apply a C prototype without a calling convention" {
    if ($protoPlain.ok) { $true } else { "HTTP $($protoPlain.status): $($protoPlain.body)" }
}
$afterProto = As-Object (Get-Json "/functions/by-address" @{ address = $target.address }).body
Check "the prototype is visible on the next read" {
    if ("$($afterProto.signature)" -match "mcp_renamed_function") { $true } else { "signature=$($afterProto.signature)" }
}
Say "  signature: $($afterProto.signature)"

$protoBad = Post-Json "/functions/set-prototype" @{ address = $target.address;
    prototype = "NoSuchTypeAtAll f(UnknownType *p)" }
Check "an unparseable prototype fails cleanly" {
    if ($protoBad.status -eq 400 -and (As-Object $protoBad.body).error) { $true }
    elseif ($protoBad.status -eq 500) { "returned 500 instead of 400: $($protoBad.body)" }
    else { "HTTP $($protoBad.status): $($protoBad.body)" }
}

$cmt = Post-Json "/functions/set-comment" @{ address = $target.address; comment = "GhidraMCP12 e2e comment" }
Check "set a function comment" {
    if ($cmt.ok) { $true } else { "HTTP $($cmt.status): $($cmt.body)" }
}
$cmtBack = As-Object (Post-Json "/comments/disassembly" @{ address = $target.address;
    comment = "GhidraMCP12 e2e disassembly comment" }).body
Check "set a disassembly (eol) comment" { if ($cmtBack.comment) { $true } else { "no comment in response" } }
$cmts = As-Object (Get-Json "/comments" @{ address = $target.address }).body
Check "read both comments back" {
    if ($cmts.eol -and $cmts.function) { $true }
    else { "eol=$($cmts.eol) function=$($cmts.function)" }
}
Say "  comments: eol='$($cmts.eol)' function='$($cmts.function)'"

$sym = Post-Json "/symbols/create" @{ address = $info.imageBase; newName = "mcp_e2e_label" }
Check "create a symbol" {
    if ($sym.ok -and (As-Object $sym.body).name -eq "mcp_e2e_label") { $true }
    else { "HTTP $($sym.status): $($sym.body)" }
}
$nsCreate = Post-Json "/namespaces/create" @{ name = "McpE2ENs" }
Check "create a namespace" {
    if ($nsCreate.ok -and (As-Object $nsCreate.body).name -eq "McpE2ENs") { $true }
    else { "HTTP $($nsCreate.status): $($nsCreate.body)" }
}
$nested = Post-Json "/namespaces/create" @{ name = "McpE2ENs::Inner" }
Check "create a nested namespace" {
    if ($nested.ok -and (As-Object $nested.body).nameWithNamespace -match "Inner") { $true }
    else { "HTTP $($nested.status): $($nested.body)" }
}

# Variables: add an explicit parameter list to the function, then rename/retype it.
$proto2 = Post-Json "/functions/set-prototype" @{ address = $target.address;
    prototype = "int __cdecl mcp_renamed_function(int mcpParamA, char *mcpParamB)" }
$vars = As-Object (Get-Json "/variables" @{ address = $target.address }).body
Check "variables are listed after the prototype is applied" {
    if ($vars.parameters -and $vars.parameters.Count -ge 2) { $true }
    else { "parameters=$($vars.parameters.Count)" }
}
Say "  parameters: $(($vars.parameters | ForEach-Object { "$($_.name):$($_.dataType)" }) -join ', ')"

$vrename = Post-Json "/variables/rename" @{ function = $target.address; oldName = "mcpParamA"; newName = "mcpCount" }
Check "rename a parameter" {
    if ($vrename.ok -and (As-Object $vrename.body).newName -eq "mcpCount") { $true }
    else { "HTTP $($vrename.status): $($vrename.body)" }
}
$vretype = Post-Json "/variables/retype" @{ function = $target.address; variable = "mcpCount"; type = "unsigned int" }
Check "retype a parameter" {
    if ($vretype.ok -and (As-Object $vretype.body).dataType) { $true }
    else { "HTTP $($vretype.status): $($vretype.body)" }
}
$vars2 = As-Object (Get-Json "/variables" @{ address = $target.address }).body
Check "the parameter change is visible on the next read" {
    $p0 = $vars2.parameters | Where-Object { $_.name -eq "mcpCount" } | Select-Object -First 1
    if ($p0) { $true } else { "names: $(($vars2.parameters | ForEach-Object { $_.name }) -join ',')" }
}
$vbad = Post-Json "/variables/retype" @{ function = $target.address; variable = "noSuchVariable"; type = "int" }
Check "retyping an unknown variable fails cleanly" {
    if ($vbad.status -eq 404 -and (As-Object $vbad.body).error) { $true }
    else { "HTTP $($vbad.status): $($vbad.body)" }
}

$bk = Post-Json "/bookmarks/create" @{ address = $target.address; comment = "mcp e2e bookmark"; type = "Note" }
Check "create a bookmark" {
    if ($bk.ok -and (As-Object $bk.body).comment -eq "mcp e2e bookmark") { $true }
    else { "HTTP $($bk.status): $($bk.body)" }
}
$bks = As-Object (Get-Json "/bookmarks" @{}).body
Check "bookmarks are listed" {
    if ([int]$bks.count -ge 1) { $true } else { "count=$($bks.count)" }
}
$bkDel = Post-Json "/bookmarks/delete" @{ address = $target.address; type = "Note"; category = "GhidraMCP12" }
Check "delete the bookmark" {
    if ($bkDel.ok) { $true } else { "HTTP $($bkDel.status): $($bkDel.body)" }
}

$goto = Post-Json "/analysis/goto" @{ address = $target.address }
Check "goto navigates (headless records the location)" {
    if ($goto.ok -and (As-Object $goto.body).address) { $true } else { "HTTP $($goto.status): $($goto.body)" }
}
$cur = As-Object (Get-Json "/analysis/current" @{}).body
Check "current location is readable after goto" {
    if ($cur.address) { $true } else { "address=$($cur.address); reason=$($cur.reason)" }
}

$dis2 = Post-Json "/analysis/disassemble" @{ address = $target.address; length = 16 }
Check "analysis/disassemble succeeds" { if ($dis2.ok) { $true } else { "HTTP $($dis2.status): $($dis2.body)" } }

$wr = Post-Json "/memory/write" @{ address = $target.address; hex = "90" }
Check "patching over defined code is refused with guidance" {
    # Ghidra will not silently overwrite an instruction, and neither should the
    # bridge: it must say so and offer the opt-in.
    $o = As-Object $wr.body
    if ($wr.status -eq 409 -and $o.error -match "clearCodeUnits=true") { $true }
    elseif ($wr.ok) { "was allowed without the opt-in" }
    else { "HTTP $($wr.status): $($wr.body)" }
}
$wr2 = Post-Json "/memory/write" @{ address = $target.address; hex = "90"; clearCodeUnits = "true" }
Check "patch a byte with clearCodeUnits=true" {
    if ($wr2.ok -and (As-Object $wr2.body).matches) { $true } else { "HTTP $($wr2.status): $($wr2.body)" }
}
$rd = As-Object (Get-Json "/data/read" @{ address = $target.address; type = "byte" }).body
Check "the patched byte reads back as 0x90" {
    if ([int]$rd.value -eq 144) { $true } else { "value=$($rd.value)" }
}

# The Java source is built by substituting a placeholder for the double-quote
# character, and is kept on ONE line. Embedding Java string literals in a
# PowerShell here-string is a trap (a double quote ends the here-string, and
# single quotes are not Java delimiters), and multi-line values passed through
# curl's --data-urlencode are clipped at the first newline on Windows. One line
# with substituted quotes avoids both.
$q = [char]34
$parts = @(
    'import ghidra.program.model.listing.CommentType;',
    'println(@mcp-e2e-script-ran on @ + currentProgram.getName());',
    'setPlateComment(currentProgram.getMinAddress(), @set by the MCP inline script@);'
)
$inlineJava = ($parts -join ' ').Replace("@", $q)
$scriptRun = Post-Json "/scripts/execute" @{ source = $inlineJava; language = "java"; timeout = 60 }
Check "run an inline Java GhidraScript (wrapped automatically)" {
    if ($scriptRun.ok -and (As-Object $scriptRun.body).output -match "mcp-e2e-script-ran") { $true }
    else { "HTTP $($scriptRun.status): $($scriptRun.body)" }
}
if ($scriptRun.ok) { Say "  script output: $(($scriptRun.body | ConvertFrom-Json).output.Trim())" }

$save = Post-Json "/program/save" @{ comment = "e2e save" }
Check "save either succeeds or explains why it cannot" {
    $o = As-Object $save.body
    if ($save.ok -and $o.success) { $true }
    elseif ($save.status -eq 409 -and $o.error -match "canSave|read-only|project") { $true }
    else { "HTTP $($save.status): $($save.body)" }
}
if (-not $save.ok) { Say "  save not possible here: $((As-Object $save.body).error)" }

# ---------------------------------------------------------------- 4. consistency
Say ""
Say "--- pass 4: consistency and error handling ---" "Cyan"

$legacyDec = Post-Json "/decompile" @{ name = "mcp_renamed_function" }
Check "decompile by name works (rename was committed)" {
    if ($legacyDec.ok -and (As-Object $legacyDec.body).decompiled) { $true }
    else { "HTTP $($legacyDec.status): $($legacyDec.body)" }
}

Check "unknown endpoint returns a JSON 404" {
    $r = Get-Json "/definitely_not_an_endpoint" @{}
    if ($r.status -eq 404 -and $r.body -match '"error"') { $true } else { "HTTP $($r.status): $($r.body)" }
}
Check "a POST to a GET-only route falls back instead of failing" {
    # MCP clients are inconsistent about verbs; every GET route is a read, so the
    # bridge accepts the POST rather than returning a 405 an agent cannot act on.
    $r = Post-Json "/types/count" @{}
    if ($r.ok) { $true } else { "HTTP $($r.status): $($r.body)" }
}
Check "bad address returns a 400/404 with a message" {
    $r = Get-Json "/functions/by-address" @{ address = "0xdeadbeefdeadbeef" }
    if ($r.status -eq 400 -or $r.status -eq 404) { $true } else { "HTTP $($r.status): $($r.body)" }
}
Check "unknown data type lists suggestions" {
    $r = Post-Json "/variables/retype" @{ function = $target.address; variable = "mcpCount"; type = "NotARealType" }
    $obj = As-Object $r.body
    if ($r.status -eq 400 -and $obj.error -match "Known examples") { $true } else { "HTTP $($r.status): $($r.body)" }
}
Check "the health endpoint still answers after all mutations" {
    $r = Get-Json "/_health" @{}
    if ($r.ok) { $true } else { "HTTP $($r.status)" }
}

# ------------------------------------------------------------------------- report
Say ""
Say "=== summary ===" "Cyan"
Say "passed : $($script:pass)"
Say "failed : $($script:fail)"
Say "warned : $($script:warn)"

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ReportFile) | Out-Null
$script:lines | Set-Content -Path $ReportFile -Encoding UTF8
Say "report : $ReportFile"

if ($script:fail -gt 0) { exit 1 }
exit 0
