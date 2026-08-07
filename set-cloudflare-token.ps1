$ErrorActionPreference = "Stop"

Write-Host "Cloudflare API Token을 입력하세요." -ForegroundColor Cyan
Write-Host "입력한 문자는 화면에 표시되지 않습니다. 붙여넣은 뒤 Enter를 누르세요."

$secureToken = Read-Host "API Token" -AsSecureString
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)

try {
  $plainToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)

  if ([string]::IsNullOrWhiteSpace($plainToken)) {
    throw "토큰이 입력되지 않았습니다."
  }

  [Environment]::SetEnvironmentVariable(
    "CLOUDFLARE_API_TOKEN",
    $plainToken,
    [EnvironmentVariableTarget]::User
  )

  $saved = [Environment]::GetEnvironmentVariable(
    "CLOUDFLARE_API_TOKEN",
    [EnvironmentVariableTarget]::User
  )

  if ([string]::IsNullOrWhiteSpace($saved)) {
    throw "환경변수 저장을 확인하지 못했습니다."
  }

  Write-Host "`n설정이 완료되었습니다. 이 창을 닫고 Codex로 돌아가세요." -ForegroundColor Green
}
catch {
  Write-Host "`n설정 실패: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
  if ($pointer -ne [IntPtr]::Zero) {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
  }
  Remove-Variable plainToken -ErrorAction SilentlyContinue
  Remove-Variable saved -ErrorAction SilentlyContinue
}

Read-Host "계속하려면 Enter"
