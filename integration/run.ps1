$ErrorActionPreference = 'Stop'
$project = 'zitadeltg-it-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$compose = @('compose', '-p', $project, '-f', "$PSScriptRoot/docker-compose.yml")
$result = 1
try {
    & docker @compose build suite bootstrap
    if ($LASTEXITCODE -ne 0) { throw 'Integration image build failed' }
    & docker @compose run --rm --use-aliases suite
    $result = $LASTEXITCODE
} finally {
    if ($result -ne 0) { & docker @compose logs --no-color zitadel postgres }
    & docker @compose down --volumes --remove-orphans
}
exit $result
