# VSCODE: ctrl/cmd+k+1 folds all functions, ctrl/cmd+k+j unfold all functions. Check '.vscode/launch.json' for any current parameters
# VSCODE: use setting ["powershell.codeFolding.showLastLine": false] to hide the trailing '}' of each function
# [CmdletBinding()]
param (
    [Parameter(Position = 0)][string]$action,           # action to execute
    [Parameter()][switch]$aws,                          # [CREATE MODE] create aws classroom for event TODO
    [Parameter()][switch] $azure,                       # [CREATE MODE] create azure classroom for event TODO
    [Parameter()][switch] $cloudCommands,               # enable to show commands
    [Parameter()][switch] $gcp,                         # [CREATE MODE] create gcp classroom for event
    [Parameter()][string] $googleCloudProjectOverride,  # override project creation to use a specific project
    [Parameter()][int] $hourLimit,                      # [REMOVE MODE] max event lifespan in hours (WARNING: THIS AFFECTS ALL EVENTS)
    [Parameter()][string] $eventName,                   # [CREATE MODE] specify event name
    [Parameter()][string] $instructorName,              # [CREATE MODE] specify instructorName (defaults to current user)
    [Parameter()][switch] $verboseMode,                 # level 0 (debug/info/errors) output (versus standard level 1 info/errors)
    [Parameter()][int] $userCount                       # [CREATE MODE] specify number of attendees (default is 3)
)

## Core Functions
function Get-Help {
    Write-Host
    Write-Host "Action required.  Options are 'create' or 'remove'."
    Write-host "example: ./harnessevents.ps1 create"
    Write-Host
}
function Get-Randomstring {
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]
        $characterCount
    )
    if (-not $characterCount) { $characterCount = 6 }
    return -join ((65..90) + (97..122) + (48..57) | Get-Random -Count $characterCount | ForEach-Object { [char]$_ })

}
function Get-Prefs($scriptPath) {
    # Do the things for the command line switches selected
    if ($verboseMode) { $script:outputLevel = 0 } else { $script:outputLevel = 1 }
    if ($cloudCommands) { $script:showCommands = $true } else { $script:showCommands = $false }
    $script:retainLog = $false
    if ($googleCloudProjectOverride) { $script:googleCloudProjectOverride }
    $script:ProgressPreference = "SilentlyContinue"
    if ($scriptPath) {
        $script:logFile = "$($scriptPath).log"
        Send-Update -t 0 -c "Log: $logFile"
        if ((test-path $logFile) -and -not $retainLog) {
            Remove-Item $logFile
        }
        $script:configFile = "$($scriptPath).conf"
        Send-Update -t 0 -c "Config: $configFile"
    }
    if ($outputLevel -eq 0) {
        $script:choiceColumns = @("Option", "description", "current", "key", "callFunction", "callProperties")
        $script:providerColumns = @("option", "provider", "name", "identifier", "userid", "default")
        $script:eventColumns = @("option","Name","Email", "ID", "default")
    }
    else {
        $script:choiceColumns = @("Option", "description", "current")
        $script:providerColumns = @("option", "provider", "name")
        $script:eventColumns = @("option","Name", "Email")
    }
    $script:config = [PSCustomObject]@{}
    $config | ConvertTo-Json | Out-File $configFile
    Send-Update -c "CREATED config" -t 0

}
function Get-UserName {
    # Generate a fun PG-rated madlibs-style username
    $Prefix = @(
        "abundant",
        "delightful",
        "high",
        "nutritious",
        "square",
        "adorable",
        "dirty",
        "hollow",
        "obedient",
        "steep",
        "agreeable",
        "drab",
        "hot",
        "living",
        "dry",
        "hot",
        "odd",
        "straight",
        "dusty",
        "huge",
        "strong",
        "beautiful",
        "eager",
        "icy",
        "orange",
        "substantial",
        "better",
        "early",
        "immense",
        "panicky",
        "sweet",
        "bewildered",
        "easy",
        "important",
        "petite",
        "swift",
        "big",
        "elegant",
        "inexpensive",
        "plain",
        "tall",
        "embarrassed",
        "itchy",
        "powerful",
        "tart",
        "black",
        "prickly",
        "tasteless",
        "faint",
        "jolly",
        "proud",
        "teeny",
        "brave",
        "famous",
        "kind",
        "purple",
        "tender",
        "breeze",
        "fancy",
        "broad",
        "fast",
        "quaint",
        "thoughtful",
        "tiny",
        "bumpy",
        "light",
        "quiet",
        "calm",
        "fierce",
        "little",
        "rainy",
        "careful",
        "lively",
        "rapid",
        "uneven",
        "chilly",
        "flaky",
        "interested",
        "flat",
        "relieved",
        "unsightly",
        "clean",
        "fluffy",
        "loud",
        "uptight",
        "clever",
        "freezing",
        "vast",
        "clumsy",
        "fresh",
        "lumpy",
        "victorious",
        "cold",
        "magnificent",
        "warm",
        "colossal",
        "gentle",
        "mammoth",
        "salty",
        "gifted",
        "scary",
        "gigantic",
        "massive",
        "scrawny",
        "glamorous",
        "screeching",
        "whispering",
        "cuddly",
        "messy",
        "shallow",
        "curly",
        "miniature",
        "curved",
        "great",
        "modern",
        "shy",
        "wide-eyed",
        "witty",
        "damp",
        "grumpy",
        "mysterious",
        "skinny",
        "wooden",
        "handsome",
        "narrow",
        "worried",
        "deafening",
        "happy",
        "nerdy",
        "heavy",
        "soft",
        "helpful",
        "noisy",
        "sparkling",
        "young",
        "delicious"
    )
      
    $Name = @(
        "apple",
        "seashore",
        "badge",
        "flock",
        "sidewalk",
        "basket",
        "basketball",
        "furniture",
        "smoke",
        "battle",
        "geese",
        "bathtub",
        "beast",
        "ghost",
        "nose",
        "beetle",
        "giraffe",
        "sidewalk",
        "beggar",
        "governor",
        "honey",
        "stage",
        "bubble",
        "hope",
        "station",
        "bucket",
        "income",
        "cactus",
        "island",
        "throne",
        "cannon",
        "cow",
        "judge",
        "toothbrush",
        "celery",
        "lamp",
        "turkey",
        "cellar",
        "lettuce",
        "umbrella",
        "marble",
        "underwear",
        "coach",
        "month",
        "vacation",
        "coast",
        "vegetable",
        "crate",
        "ocean",
        "plane",
        "donkey",
        "playground",
        "visitor",
        "voyage"
    )      
    return "$(Get-Random -inputObject $Prefix)$(Get-Random -inputObject $Name)"
}
function Set-Prefs {
    # Set a new keypair value. retrieve with $config.<yourkey>
    # Values are stored in <script>.conf
    param(
        $k, # key
        $v # value
    )
    if ($v) {
        Send-Update -c "Updating key: $k -> $v" -t 0
        #$config[$k] = $v
        $config | Add-Member -MemberType NoteProperty -Name $k -Value $v -Force
    }
    else {
        if ($k -and $config.$k) {
            Send-Update -c "Deleting config key: $k" -t 0
            #$config.remove($k)
            $config.PSObject.Properties.Remove($k)
        }
        else {
            Send-Update -c "Key didn't exist: $k" -t 0
        }
    }     
    if ($MyInvocation.MyCommand.Name) {
        $config | ConvertTo-Json | Out-File $configFile
    }
    else {
        Send-Update -c "No command name, config will not be saved" -t 0
    }
}
function Send-Update {
    # Handle output to screen & log, execute commands to cloud systems and return results
    param(
        [string] $content, # Message content to log/write to screen
        [int] $type, # [0/1/2] log levels respectively: debug/info/errors, info/errors, errors
        [string] $run, # Run a command and return result
        [switch] $append, # [$true/false] skip the newline (next entry will be on same line)
        [switch] $errorSuppression, # use this switch to suppress error output (useful for extraneous warnings)
        [switch] $outputSuppression, # use to suppress normal output
        [switch] $whatIf # do NOT run command, just SHOW for troubleshooting
    )
    $Params = @{}
    if ($whatIf) { $whatIfComment = "!WHATIF! " }
    if ($run) { $Params['ForegroundColor'] = "Magenta"; $start = "[$whatIfComment>]" }
    else {
        Switch ($type) {
            0 { $Params['ForegroundColor'] = "DarkBlue"; $start = "[.]" }
            1 { $Params['ForegroundColor'] = "DarkGreen"; $start = "[-]" }
            2 { $Params['ForegroundColor'] = "DarkRed"; $start = "[X]" }
            default { $Params['ForegroundColor'] = "Gray"; $start = "" }
        }
    }
    if ($outputlevel -eq 0) {
        $CallStack = Get-PSCallStack
        if ($CallStack.Count -gt 1) {
            $CallingFunctionName = $CallStack[1].FunctionName
            $functionName = " <$($CallingFunctionName)>"
        }
        else {
            $functionName = " <Called Directly>"
        }
        $start = "$start$functionName"
    }
    # Format the command to show on screen if user wants to see it
    if ($run -and $showCommands) { $showcmd = " [ $run ] " }
    if ($currentLogEntry) { $screenOutput = "$content$showcmd" } else { $screenOutput = "   $start $content$showcmd" }
    if ($append) { $Params['NoNewLine'] = $true; $script:currentLogEntry = "$script:currentLogEntry $content$showcmd"; }
    if (-not $append) {
        #This is the last item in-line.  Write it out if log exists
        if ($logFile) {
            "$(get-date -format "yyyy-MM-dd HH:mm:ss"): $currentLogEntry $content$showcmd" | out-file $logFile -Append
        }
        #Reset inline recording
        $script:currentLogEntry = $null
    }
    # output if user wants to see this level of content
    if ($type -ge $outputLevel) {
        write-host @Params $screenOutput
    }
    if ($whatIf) { return }
    if ($run -and $errorSuppression -and $outputSuppression) { return invoke-expression $run 1>$null }
    if ($run -and $errorSuppression) { return invoke-expression $run 2>$null }
    if ($run -and $outputSuppression) { 
        if ($run.substring(0,6) -eq "gcloud") {
            #Add Google's custom output suppression
            $run = $run + " --no-user-output-enabled"
        }
        return invoke-expression $run 1>$null 
    }
    if ($run) { return invoke-expression $run }
}
function Test-PreFlight {
    # Make sure commands needed are available
    # TODO add aws and azure commands when finished
    if (Get-Command gcloud -ErrorAction SilentlyContinue) {
        Send-Update -t 1 -c "gcloud commands available!"
    }
    else {
        Send-Update -t 2 -c "gcloud commands not found. install via mac with: brew install --cask google-cloud-sdk"
        exit
    }
    # Check if using cloudsdk but there is a normal user account.  Switch if so.
    $currentUser = gcloud auth list --format='value(account)' --filter=status=active
    $harnessUser = gcloud auth list --filter=account:'harness.io' --format='value(account)'
    if ($currentUser.contains("cloudsdk") -and $harnessUser.count -eq 1) {
        gcloud config set account $harnessUser --no-user-output-enabled
    }
    
}
function Save-Event {
    Set-Prefs -k "EventCreateTime" -v $(Get-Date)
    $datePrefix = $(Get-Date -Uformat "%Y-%m")
    $fileName = $config.GoogleUser.split("@")[0] + "-" + $config.EventName + ".json"
    gcloud storage cp $configFile gs://harnesseventsdata/events/open/$datePrefix-$fileName
}

## Actions
function Get-HeadlessMode {
    Send-Update -t 1 -c "Creating new event"
    # Error out with any problems
    $ErrorActionPreference = "Stop"
    # Use cli provided instructor name if present
    if ($instructorName) {
        $currentUser = $instructorName
    }
    else { 
        # this will use the cloudsdk account- typically used for daily testing
        $currentUser = gcloud auth list --format='value(account)' --filter=status=active
    }
    if (-not $currentUser) {
        Send-Update -t 2 -c "No google user authentication found.  Is it illegal in 23 US states to continue without one.  Nice try though."
        Send-Update -t 2 -c "Run <gcloud auth login> and login with your work email."
        exit
    }
    # Make sure user isn't trying to run this as cloudsdk
    if ($currentUser.Contains("cloudsdk")) {
        Send-Update -t 2 -c "You're running as the HarnessEvents CloudSDK service account."
        Send-Update -t 2 -c "Switch to your work account with <gcloud config set account 'your email'>"
        exit
    }
    # Start saving configuration
    Set-Prefs -k "GoogleUser" -v $currentUser
    Set-Prefs -k "InstructorEmail" -v "$($currentUser.split("@")[0])@harnessevents.io"
    # Set user count
    if ($userCount) { Set-Prefs -k "UserEventCount" -v $userCount }
    else { Set-Prefs -k "UserEventCount" -v 1 }
    # Set event name
    if (-not $eventName) {
        $eventName = Get-UserName
        Send-Update -t 1 -c "Generated event name: $eventName" 
    }
    $formattedEventName = $eventName -replace '\W', ''
    $formattedEventName = "event-" + $formattedEventName.tolower()
    Set-Prefs -k "EventName" -v $formattedEventName
    $eventEmail = $formattedEventName + "@harnessevents.io"
    Set-Prefs -k "EventEmail" -v $eventEmail
    if ($gcp) { Set-Prefs -k "GoogleClassroom" -v "ENABLED" }
    if ($aws) { Set-Prefs -k "AwsClassroom" -v "ENABLED" }
    if ($azure) { Set-Prefs -k "AzureClassroom" -v "ENABLED" }
    # Get Google Access token
    Get-GoogleAccessToken
    # Save event details to 'open' events json folder
    Save-Event
    # Create the event
    New-Event
    #Test-Connectivity -harnessToken $config.HarnessEventsPAT | Out-Null
    #Sync-Event
    if ($config.GoogleUser.contains("@harness.io")) {
        Send-Update -t 1 -c "Switching to original account" -r "gcloud config set account $($config.GoogleUser) --no-user-output-enabled"
    }
    Send-Update -t 1 -c "End Headless Mode"
    exit
}

## Event Functions
function Add-UserToGroup {
    param (
        [Parameter(Mandatory = $true)]
        [string] $userEmail,
        [Parameter()]
        [string] $groupEmail,
        [switch] $owner
    )
    # Retrieve group key
    if ($groupEmail) {
        $groupKey = Get-GroupKey -g $groupEmail
    }
    else {
        $groupKey = $config.GoogleEventId
    }
    if (!$groupKey) {
        Send-Update -t 2 -c "Group Key is missing! Cannot proceed"
        exit
    }
    # Build api call for group
    $uri = "https://admin.googleapis.com/admin/directory/v1/groups/$groupKey/members"
    Send-Update -t 0 -c "Email $userEmail being added to Group URI: $uri"
    if ($owner) { $role = "OWNER" } else { $role = "MEMBER" }
    $body = @{
        "email" = $userEmail
        "role"  = $role
    } | ConvertTo-Json
    Send-Update -t 0 -c "Body: $body"
    $response = Invoke-RestMethod -Method 'Post' -ContentType 'application/json' -Uri $uri -Body $body -Headers $headers
    return $response
}
function Get-GoogleAccessToken {
    # Check for valid token
    if ($config.GoogleAccessToken -and $config.GoogleAccessTokenTimestamp) {
        # Check if token is over 30m old
        $TimeDiff = $(Get-Date) - $config.GoogleAccessTokenTimestamp
        if ($TimeDiff.TotalMinutes -lt 30) {
            Send-Update -t 0 -c "Google Workspace Token age is OK: $([math]::round($TimeDiff.TotalMinutes))m."
            $script:headers = @{ "Authorization" = "Bearer $($config.GoogleAccessToken)" }
            return
        }
        else {
            Send-Update -t 1 -c "Google Workspace Token is too old: $([math]::round($TimeDiff.TotalMinutes))m."
        }
    }
    else {
        Send-Update -t 1 -c "Token or timestemp missing."
    }
    # Refresh token if older than 30m
    Send-Update -t 1 -c "Refreshing token"
    if ($config.GoogleUser -and $config.GoogleUser.contains("@harness.io")) {
        $initProject = gcloud projects list --filter='name:sales' --format=json | Convertfrom-Json
    }
    if ($config.GoogleUser.contains("cloudsdk")) {
        $initProject = gcloud projects list --filter='name:administration' --format=json | Convertfrom-Json
    }
    if ($initProject.count -ne 1) {
        Send-Update -t 2 -c "Failed to find project. Try running (gcloud auth login) using your work email."
        exit
    }
    Send-Update -t 1 -c "Retrieving credentials" -r "gcloud secrets versions access latest --secret='HarnessEventsAccount' --project=$($initProject.projectId)" | Out-File -FilePath harnessevents.json
    if (!(Test-Path("harnessevents.json"))) {
        Send-Update -t 2 -c "HarnessEventsAccount not found. You might need to run 'gcloud auth login' again with your work email."
        exit
    }
    Send-Update -t 1 -c "Activating service account" -r "gcloud auth activate-service-account --key-file=harnessevents.json --no-user-output-enabled"
    $project = gcloud projects list --filter='name:administration' --format=json | Convertfrom-Json
    Set-Prefs -k "AdminProjectId" -v $($project.projectId)
    # Sneak in grabbing the Harness Feature Flag token and HarnessEvents PATeven though this is a google function. shhhhh!
    if (-not $config.HarnessFFToken) {
        $HarnessFFToken = Send-Update -t 1 -c "Retrieving credentials" -r "gcloud secrets versions access latest --secret='HarnessEventsFF' --project=$($config.AdminProjectId)" 
        Set-Prefs -k "HarnessFFToken" -v $HarnessFFToken
    }
    if (-not $config.HarnessEventsPAT) {
        $HarnessEventsPAT = Send-Update -t 1 -c "Snagging HarnessEvents PAT" -r "gcloud secrets versions access latest --secret='HarnessEventsPAT' --project=$($config.AdminProjectId)"
        Set-Prefs -k "HarnessEventsPAT" -v $HarnessEventsPAT
    }
    $authorizationCode = Send-Update -t 1 -c "Retrieving account token" -r "gcloud auth print-access-token --scopes='https://www.googleapis.com/auth/admin.directory.user https://www.googleapis.com/auth/admin.directory.group'"
    if ($authorizationCode) {
        # Save valid token
        Set-Prefs -k "GoogleAccessToken" -v $authorizationCode
        Set-Prefs -k "GoogleAccessTokenTimestamp" -v $(Get-date)
        # Save the name of the google account to use later
        $googleServiceAccount = gcloud auth list --filter=status:ACTIVE --format='value(account)'
        Set-Prefs -k "GoogleServiceAccount" -v $googleServiceAccount
        # Write out auth headers that can be used anywhere
        $script:headers = @{
            "Authorization" = "Bearer $($config.GoogleAccessToken)"
        }
        Send-Update -t 0 -c "Successfully retrieved a new token and timestamp."
    }
    else {
        Send-Update -t 2 -c "Unexpected error while retrieving access token."
    }
    # Weird issues with project errors even when specifying project in cases where "cached" project was removed.  I hate you, Google.
    gcloud config set project $config.AdminProjectId --no-user-output-enabled
    $credentialsJson = Get-Content 'harnessevents.json' -Raw | Convertfrom-Json
    Set-Prefs -k "ServiceAccountEmail" -v $credentialsJson.client_email
    $PrivateKey = $credentialsJson.private_key -replace '-----BEGIN PRIVATE KEY-----\n' -replace '\n-----END PRIVATE KEY-----\n' -replace '\n'
    Set-Prefs -k "ServiceAccountKey" -v $PrivateKey
    # Cleanup due to Google's stupid requirement that the json be an actual *file*.  Eat it, Google.
    if (Test-Path -Path harnessevents.json) { Remove-Item harnessevents.json }
}
function Get-GoogleApiAccessToken {
    if ($config.GoogleAppToken -and $config.GoogleAppTokenTimestamp) {
        # Check if token is over 50m old
        $TimeDiff = $(Get-Date) - $config.GoogleAppTokenTimestamp
        if ($TimeDiff.TotalMinutes -lt 30) {
            $script:appHeaders = @{
                "Authorization"       = "Bearer $($config.GoogleAppToken)"
                "x-goog-user-project" = $($config.AdminProjectId)
            }
            Send-Update -t 0 -c "Google App Token age is OK: $([math]::round($TimeDiff.TotalMinutes))m."
            return
        }
        else {
            Send-Update -t 1 -c "Google App Token is too old: $([math]::round($TimeDiff.TotalMinutes))m."
        }
    }
    else {
        Send-Update -t 1 -c "New token needed"
    }
    $PrivateKey = $config.ServiceAccountKey
    $header = @{
        alg = "RS256"
        typ = "JWT"
    }
    $headerBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($header | ConvertTo-Json)))
    $timestamp = [Math]::Round((Get-Date -UFormat %s))
    $claimSet = @{
        iss   = $config.ServiceAccountEmail
        scope = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/spreadsheets"
        aud   = "https://oauth2.googleapis.com/token"
        exp   = $timestamp + 3600
        iat   = $timestamp
        # sub   = $TargetUserEmail
    }
    $claimSetBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($claimSet | ConvertTo-Json)))
    $signatureInput = $headerBase64 + "." + $claimSetBase64
    $signatureBytes = [System.Text.Encoding]::UTF8.GetBytes($signatureInput)
    $privateKeyBytes = [System.Convert]::FromBase64String($PrivateKey)
    $rsaProvider = [System.Security.Cryptography.RSA]::Create()
    $bytesRead = $null
    $rsaProvider.ImportPkcs8PrivateKey($privateKeyBytes, [ref]$bytesRead)
    $signature = $rsaProvider.SignData($signatureBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $signatureBase64 = [System.Convert]::ToBase64String($signature)
    $jwt = $headerBase64 + "." + $claimSetBase64 + "." + $signatureBase64
    $body = @{
        grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
        assertion  = $jwt
    }
    $response = Invoke-RestMethod -Uri "https://oauth2.googleapis.com/token" -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
    $script:appHeaders = @{
        Authorization         = 'Bearer {0}' -f $response.access_token
        "x-goog-user-project" = $($config.AdminProjectId)
    }
    # Save valid token
    Set-Prefs -k "GoogleAppToken" -v $response.access_token
    Set-Prefs -k "GoogleAppTokenTimestamp" -v $(Get-date)
}
function Get-GroupMembers {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string] $groupEmail,
        [Parameter()]
        [switch] $splitIntoGroups # organize the results into owners/members and provide a count
    )
    Get-GoogleAccessToken
    # Retrieve group key - or use cached default if none provided
    if ($groupEmail) {
        $groupKey = Get-GroupKey -g $groupEmail
    }
    else {
        $groupKey = $config.GoogleEventId
    }
    $uri = "https://admin.googleapis.com/admin/directory/v1/groups/$groupKey/members"
    Send-Update -t 0 -c "Getting group members with uri: $uri"
    $response = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers
    if ($response.members) {
        if ($splitIntoGroups) {
            $groupMembers = @{
                "owners"      = $response.members | Where-Object { $_.role -eq "OWNER" }
                "members"     = $response.members | Where-Object { $_.role -eq "MEMBER" }
                "ownerCount"  = ($response.members | Where-Object { $_.role -eq "OWNER" }).count
                "memberCount" = ($response.members | Where-Object { $_.role -eq "MEMBER" }).count
                "groupKey"    = $groupKey
            }
            return $groupMembers
        }
        else {
            return $response.members
        }
        
    }
    return $false
}
function Get-User {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $userName
    )
    if (!$userName.contains("harnessevents.io")) { $userName = "$userName@harnessevents.io" }
    $uri = "https://admin.googleapis.com/admin/directory/v1/users?domain=harnessevents.io&query=email='$userName'"
    Send-Update -t 0 -c "Looking up user with uri: $uri"
    $response = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers
    if ($response.users) {
        return $response.users
    }
    return $false
}
function New-Group {
    # Create a new group and confirm it is reachable via API before returning
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $email,
        [Parameter()]
        [string]
        $name
    )
    if (!$name) { $name = "new-group" }
    $body = @{
        "email" = $email
        "name"  = $name
    } | ConvertTo-Json
    $uri = "https://admin.googleapis.com/admin/directory/v1/groups?domain=harnessevents.io&query=email='$email'"
    $response = Invoke-RestMethod -Method 'Post' -ContentType 'application/json' -Uri $uri -Body $body -Headers $headers
    Send-Update -t 0 -c "Create new group returned: $response"
    $success = $false
    $counter = 0
    Do {
        Send-Update -t 1 -c "Waiting for group creation..."
        $response = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers
        if ($response.groups) {
            Send-Update -t 1 -c "Group $email created successfully!"
            Set-Prefs -k "GoogleEventName" -v $response.groups.name
            Set-Prefs -k "GoogleEventId" -v $response.groups.id
            Set-Prefs -k "GoogleEventEmail" -v $response.groups.email
            $success = $true
        }
        else {
            $counter++
            if ($counter -gt 30) {
                Send-Update -t 2 -c "Group creation failed after 10 tries!"
                exit
            }
            Start-sleep -s 3
        }
    } until ($success)
    #Get-UserGroups
}
function New-Event {
    # Create instructor email for this user if it doesn't exist
    if (!(Get-User -u $config.InstructorEmail)) {
        New-User -u $config.InstructorEmail
        Send-Update -t 1 -c "Generated your instructor email: $($config.InstructorEmail)"  
    }
    # Create group if needed
    $uri = "https://admin.googleapis.com/admin/directory/v1/groups?domain=harnessevents.io&query=email='$($config.EventEmail)'"
    Send-Update -t 0 -c "Checking group email with uri: $uri"
    $response = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers
    if (!$response.groups) {
        New-Group -e $config.EventEmail -n $config.EventName
        Add-UserToGroup -u $config.InstructorEmail -o | out-null
        Send-Update -t 1 -c "Waiting for $($config.InstructorEmail) to be registered as group owner"
        while (-not $groupReady) {
            # Wait until slow ass google registers the new group owner. zzzz.....
            $membershipCheck = (Get-UserGroups -u $config.InstructorEmail | Where-Object { $_.email -eq $newEmail }).count
            if ($membershipCheck -eq 1) {
                $groupReady = $true
            }
            else {
                Send-Update -t 1 -c "User not yet registered..."
                Start-Sleep -s 6
            }
        }
        Send-Update -t 1 -c "Successfully added user: $($config.InstructorEmail) as owner."
    }
    else {
        # Event already exists- if someone else is trying to overwrite this owner's event, bail out
        $members = Get-GroupMembers -groupEmail $config.EventEmail -splitIntoGroups
        if ($members.owners.notContains($config.InstructorEmail)) {
            Send-Update -t 2 -c "This event is owned by: $($members.owners)"
        }
        exit
    }
    # else {
    #     if ($config.EventName -eq "deploytest") {
    #         # Need to get this even if about to fail so removal works
    #         $eventId = Get-GroupKey -g $newEmail
    #         Set-Prefs -k "GoogleEventId" -v $eventId
    #         Set-Prefs -k "GoogleEventEmail" -v $newEmail
    #         Send-Update -t 2 -c "Previous automated test did not successfully delete event email: $newEmail"
    #         Exit 1
    #     }
    #     if ($config.EventName) {
    #         $nameselected = $newEmail
    #     }
    # }
    # # }
    $eventId = Get-GroupKey -g $($config.EventName)
    Set-Prefs -k "GoogleEventId" -v $eventId
    Get-Events
}
function New-User {
    # Create a new google workspace user
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $userEmail
    )
    $uri = 'https://admin.googleapis.com/admin/directory/v1/users'
    $body = @{
        "primaryEmail"              = $userEmail
        "name"                      = @{
            "givenName"  = "Harness"
            "familyName" = "Events"
        }
        "suspended"                 = $false
        "password"                  = "Harness!"
        "changePasswordAtNextLogin" = $false
    } | ConvertTo-Json
    $response = Invoke-RestMethod -Method 'Post' -ContentType 'application/json' -Uri $uri -Body $body -Headers $headers
    return $response
}

## Main
Test-PreFlight
Get-Prefs($Myinvocation.MyCommand.Source)
switch ($action) {
    "create" { Get-HeadlessMode }
    "remove" {}
    Default { Get-Help }
}
