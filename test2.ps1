#$FilePath = 'worker1.json'
#$FieldName = 'file'
#$ContentType = 'text/plain'
$uri = "https://app.harness.io/ng/api/v2/secrets/files?accountIdentifier=fjf_VfuITK2bBrMLg5xV7g&orgIdentifier=event_googletest"
# $FileStream = [System.IO.FileStream]::new($filePath, [System.IO.FileMode]::Open)
#$uri = "https://webhook.site/4ceccbdc-2bbe-4be1-b3a9-7b72b93baf4a?accountIdentifier=fjf_VfuITK2bBrMLg5xV7g&orgIdentifier=event_googletest"

# $FileHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new('form-data')
# $FileHeader.Name = $FieldName
# $FileHeader.FileName = Split-Path -Leaf $FilePath
# $FileContent = [System.Net.Http.StreamContent]::new($FileStream)
# $FileContent.Headers.ContentDisposition = $FileHeader
# $FileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($ContentType)
# $FileContent.Headers.Add("x-api-key", "pat.fjf_VfuITK2bBrMLg5xV7g.685eb2c56cbe10049b61e958.zBDRQLxrtoOtPkQE9qHy")

# $MultipartContent = [System.Net.Http.MultipartFormDataContent]::new()
# $MultipartContent.Add($FileContent)

#$Response = Invoke-WebRequest -Body $MultipartContent -Method 'POST' -Uri $uri
###
$spec = @{
    secret = @{
        type          = 'SecretFile'
        name          = 'apiimport'
        identifier    = 'apiimport'
        orgIdentifier = 'event_googletest'
        spec          = @{
            #errorMessageForInvalidYaml = "string"
            secretManagerIdentifier = "org.harnessSecretManager"
            #type = "SecretTextSpec1"
            #valueType = "Inline"
            #value = $secretValue
        }
    }
} | ConvertTo-Json

$multipartContent = [System.Net.Http.MultipartFormDataContent]::new()

$stringHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
$stringHeader.Name = "spec"
$StringContent = [System.Net.Http.StringContent]::new($spec)
$StringContent.Headers.ContentDisposition = $stringHeader
#$StringContent.Headers.Add("x-api-key", "pat.fjf_VfuITK2bBrMLg5xV7g.685eb2c56cbe10049b61e958.zBDRQLxrtoOtPkQE9qHy")
$multipartContent.Add($stringContent)

# $stringHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
# $stringHeader.Name = "name"
# $StringContent = [System.Net.Http.StringContent]::new("apiimport")
# $StringContent.Headers.ContentDisposition = $stringHeader
# $multipartContent.Add($stringContent)

# $stringHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
# $stringHeader.Name = "identifier"
# $StringContent = [System.Net.Http.StringContent]::new("apiimport")
# $StringContent.Headers.ContentDisposition = $stringHeader
# $multipartContent.Add($stringContent)

# $stringHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
# $stringHeader.Name = "orgIdentifier"
# $StringContent = [System.Net.Http.StringContent]::new("event_googletest")
# $StringContent.Headers.ContentDisposition = $stringHeader
# $multipartContent.Add($stringContent)

# $stringHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
# $stringHeader.Name = "spec"
# $StringContent = [System.Net.Http.StringContent]::new("{""secretManagerIdentifier"":""org.harnessSecretManager""}")
# $StringContent.Headers.ContentDisposition = $stringHeader
# $multipartContent.Add($stringContent)

$multipartFile = 'worker1.json'
$FileStream = [System.IO.FileStream]::new($multipartFile, [System.IO.FileMode]::Open)
$fileHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
$fileHeader.Name = "file"
$fileHeader.FileName = 'worker1.json'
$fileContent = [System.Net.Http.StreamContent]::new($FileStream)
$fileContent.Headers.ContentDisposition = $fileHeader
$fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("text/plain")
$multipartContent.Add($fileContent)
$templateheaders = @{
    'x-api-key' = "pat.fjf_VfuITK2bBrMLg5xV7g.685eb2c56cbe10049b61e958.zBDRQLxrtoOtPkQE9qHy"
}

Invoke-WebRequest -Uri $uri -Body $multipartContent -Method 'POST' -headers $templateheaders