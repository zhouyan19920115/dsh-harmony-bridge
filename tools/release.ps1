<#
.SYNOPSIS
  DSH 插件一条命令发版：升版本 → 提交 + 打 tag + 推送 → 更新市场 index.json → 推送。

.DESCRIPTION
  在插件仓库根目录跑：

    powershell -NoProfile -ExecutionPolicy Bypass -File tools\release.ps1 -Bump patch
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\release.ps1 -Version 0.2.0
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\release.ps1 -Bump minor -DryRun

  可选参数：
    -Token <github_token>  推送并（可选）创建 GitHub Release；不传就交给本机 git 凭据管理器。
    -Release              用 -Token 时顺便创建 GitHub Release（默认不创建）。
    -SkipIndex            只升插件版本，不改市场 index.json。

.NOTES
  index.json 里的 source.commit 必须指向“包含新版本代码的那次提交”，
  所以脚本先提交代码并拿到 commit sha，再写 index.json 并第二次提交。
#>
param(
  [ValidateSet('patch', 'minor', 'major')]
  [string]$Bump = 'patch',
  [string]$Version = '',
  [string]$Token = '',
  [switch]$Release,
  [switch]$SkipIndex,
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# ---------- 找 git ----------
$git = 'git'
try {
  & $git --version *> $null
  if ($LASTEXITCODE -ne 0) { throw 'git not found' }
} catch {
  $candidates = @(
    'D:\APP\Git\cmd\git.exe',
    'C:\Program Files\Git\cmd\git.exe',
    'C:\Program Files (x86)\Git\cmd\git.exe'
  )
  $found = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
  if (-not $found) { throw '找不到 git.exe，请把 git 加进 PATH' }
  $git = $found
}

function Invoke-Git {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
  & $git @Args
  if ($LASTEXITCODE -ne 0) { throw "git $($Args -join ' ') 失败 (exit $LASTEXITCODE)" }
}

function Get-Text([string]$path) {
  return [System.IO.File]::ReadAllText($path)
}

function Save-Text([string]$path, [string]$text) {
  [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
}

# ---------- 基本检查 ----------
$root = (Invoke-Git rev-parse --show-toplevel).Trim()
Set-Location $root
$pkgPath = Join-Path $root 'package.json'
$indexPath = Join-Path $root 'index.json'
if (-not (Test-Path $pkgPath)) { throw "不是插件仓库根目录（没有 package.json）: $root" }

$branch = (Invoke-Git branch --show-current).Trim()
if ($branch -ne 'main') { throw "请切到 main 分支再发版（当前: $branch）" }

$dirty = (Invoke-Git status --porcelain).Trim()
if ($dirty.Length -gt 0) { throw "工作区不干净，先提交或还原：`n$dirty" }

# ---------- 版本 ----------
$pkg = Get-Text $pkgPath | ConvertFrom-Json
$current = [string]$pkg.version
if ($Version.Length -gt 0) {
  $next = $Version.TrimStart('v')
} else {
  $parts = $current.Split('.')
  if ($parts.Length -ne 3) { throw "package.json 版本不是 x.y.z: $current" }
  $major = [int]$parts[0]; $minor = [int]$parts[1]; $patchVersion = [int]$parts[2]
  switch ($Bump) {
    'major' { $major++; $minor = 0; $patchVersion = 0 }
    'minor' { $minor++; $patchVersion = 0 }
    default { $patchVersion++ }
  }
  $next = "$major.$minor.$patchVersion"
}
if ($next -eq $current) { throw "新版本和当前版本一样: $current" }

Write-Host "发版: $current -> $next" -ForegroundColor Cyan
if ($DryRun) {
  Write-Host '[DryRun] 只打印，不改任何文件、不推送。' -ForegroundColor Yellow
}

# ---------- 1. 写版本号 ----------
$pkgJson = Get-Text $pkgPath
$pkgJson = [regex]::Replace($pkgJson, '("version"\s*:\s*")[^"]*(")', { param($m) $m.Groups[1].Value + $next + $m.Groups[2].Value }, 1)
if ($DryRun) {
  Write-Host "[DryRun] 会写 package.json: version = $next"
} else {
  Save-Text $pkgPath $pkgJson
}

# ---------- 2. 提交 + tag + 推送 ----------
$tag = "v$next"
if ($DryRun) {
  Write-Host "[DryRun] git commit -m release $tag && git tag $tag && git push origin main $tag"
  $commit = '<dry-run>'
} else {
  Invoke-Git add package.json
  Invoke-Git commit -m "release: $tag"
  Invoke-Git tag $tag
  if ($Token.Length -gt 0) {
    $origin = (Invoke-Git remote get-url origin).Trim()
    $pushUrl = $origin -replace '^https://', "https://x-access-token:$Token@"
    Invoke-Git push $pushUrl "main"
    Invoke-Git push $pushUrl $tag
  } else {
    Invoke-Git push origin main
    Invoke-Git push origin $tag
  }
  $commit = (Invoke-Git rev-parse HEAD).Trim()
  Write-Host "已推送 $tag (commit $commit)" -ForegroundColor Green
}

# ---------- 3. 更新市场 index.json ----------
if (-not $SkipIndex) {
  if (-not (Test-Path $indexPath)) {
    Write-Host '没有 index.json，跳过市场索引更新' -ForegroundColor Yellow
  } elseif ($DryRun) {
    Write-Host "[DryRun] 会更新 index.json: version=$next publishTimestamp=<now> source.commit=$commit"
  } else {
    $index = Get-Text $indexPath | ConvertFrom-Json
    $plugin = $index.plugins[0]
    $entry = $plugin.versions[0]
    $entry.version = $next
    $entry.publishTimestamp = [int][double]::Parse((Get-Date -UFormat %s))
    if ($entry.source) {
      $entry.source.commit = $commit
    }
    Save-Text $indexPath ($index | ConvertTo-Json -Depth 15)
    Invoke-Git add index.json
    Invoke-Git commit -m "market: release $tag (commit $commit)"
    if ($Token.Length -gt 0) {
      $origin = (Invoke-Git remote get-url origin).Trim()
      $pushUrl = $origin -replace '^https://', "https://x-access-token:$Token@"
      Invoke-Git push $pushUrl main
    } else {
      Invoke-Git push origin main
    }
    Write-Host '市场 index.json 已更新并推送' -ForegroundColor Green
  }
}

# ---------- 4. 可选: GitHub Release ----------
if ($Release -and $Token.Length -gt 0 -and -not $DryRun) {
  $origin = (Invoke-Git remote get-url origin).Trim()
  if ($origin -match 'github\.com[:/](?<owner>[^/]+)/(?<repo>[^/.]+?)(\.git)?$') {
    $owner = $Matches['owner']; $repo = $Matches['repo']
    $body = @{
      tag_name = $tag
      name = $tag
      body = "Published dsh-harmony-bridge $tag from the DSH market index."
    } | ConvertTo-Json
    $headers = @{ Authorization = "token $Token"; 'User-Agent' = 'dsh-release'; Accept = 'application/vnd.github+json' }
    try {
      Invoke-RestMethod -Method Post -Uri "https://api.github.com/repos/$owner/$repo/releases" -Headers $headers -Body $body -ContentType 'application/json' | Out-Null
      Write-Host "GitHub Release $tag 已创建" -ForegroundColor Green
    } catch {
      Write-Host "创建 GitHub Release 失败(不影响发版): $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }
}

Write-Host "完成: $tag" -ForegroundColor Green
