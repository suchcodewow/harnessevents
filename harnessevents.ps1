# VSCODE: ctrl/cmd+k+1 folds all functions, ctrl/cmd+k+j unfold all functions. Check '.vscode/launch.json' for any current parameters
# VSCODE: use setting ["powershell.codeFolding.showLastLine": false] to hide the trailing '}' of each function
# [CmdletBinding()]
param (
    [Parameter(Position = 0)][string]$action,           # action to execute
    [Parameter()][switch]$aws,                          # [CREATE MODE] create aws classroom for event TODO
    [Parameter()][switch] $azure,                       # [CREATE MODE] create azure classroom for event TODO
    [Parameter()][switch] $cloudCommands,               # enable to show commands
    [Parameter()][string] $HarnessCustomPAT,            # [CREATE MODE] harness PAT (default is community HarnessEvents account)
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
    #$script:ProgressPreference = "SilentlyContinue"
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
    if (Test-Path $configFile) {
        Send-Update -c "Reading config" -t 0
        $script:previousConfig = Get-Content $configFile -Raw | ConvertFrom-Json
    }
    $script:config = [PSCustomObject]@{}
    $config | ConvertTo-Json | Out-File $configFile
    $carryoverVariables = @(
        "GoogleAccessToken",
        "GoogleAccessTokenTimestamp",
        "GoogleAppToken",
        "GoogleAppTokenTimestamp",
        "AdminProjectId",
        "HarnessFFToken",
        "HarnessEventsPAT",
        "GoogleAccessToken",
        "GoogleServiceAccount",
        "ServiceAccountEmail",
        "ServiceAccountKey")
    foreach ($c in $carryoverVariables) {
        if ($previousConfig.$c) { Set-Prefs -k $c -v $previousConfig.$c } else { $script:refreshToken = $true }
    }
    # if we're missing any variables trigger a full refresh
    if ($refreshToken) { Set-Prefs -k "GoogleAccessToken" }
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
            3 { $Params['ForegroundColor'] = "DarkRed"; $start = "[XX] Existing with error: " }
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
    # If this is a terminal error, write environment variable for Harness to use and exit
    if ($type -eq 3) {
        $env:terminalError = $content
        Send-Update -t 2 -c "Error written to environment variables: terminalError."
        exit
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
    Send-Update -t 1 -c "Setting up config for new event."
    # Error out with any problems
    $ErrorActionPreference = "Stop"
    # Use cli provided instructor name if present
    $cliUser = gcloud auth list --format='value(account)' --filter=status=active
    Set-Prefs -k "CLIUser" -v $cliUser
    if ($instructorName) {
        $currentUser = $instructorName
    }
    else { 
        # this will use the cloudsdk account- typically used for daily testing
        $currentUser = $cliUser
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
    Send-Update -t 0 -c "Successfully identified current user: $currentUser"
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
    Set-Prefs -k "GoogleEventName" -v $formattedEventName
    # Save Harness org name
    Set-Prefs -k "HarnessOrg" -v "$($config.GoogleEventName.tolower().replace("-","_"))"
    $eventEmail = $formattedEventName + "@harnessevents.io"
    Set-Prefs -k "GoogleEventEmail" -v $eventEmail
    if ($gcp) { Set-Prefs -k "GoogleClassroom" -v $config.HarnessOrg.replace("_","-") }
    if ($aws) { Set-Prefs -k "AwsClassroom" -v $config.HarnessOrg.replace("_","-") }
    if ($azure) { Set-Prefs -k "AzureClassroom" -v $config.HarnessOrg.replace("_","-") }
    # Get Google Access token
    Get-GoogleAccessToken
    # Save event details to 'open' events json folder
    Save-Event
    # Create the event
    New-Event
    # Check connectivity
    if ($HarnessCustomPAT) {
        Send-Update -t 1 -c "Using provided Harness PAT"
        $harnessToken = $HarnessCustomPat 
    }
    else {
        Send-Update -t 1 -c "Using community Harness Account"
        $harnessToken = $config.HarnessEventsPAT 
    }
    Test-Connectivity -harnessToken $harnessToken | Out-Null
    #Sync-Event
    if ($config.GoogleUser.contains("@harness.io")) {
        Send-Update -t 1 -c "Switching to original account" -r "gcloud config set account $($config.GoogleUser) --no-user-output-enabled"
    }
    Send-Update -t 1 -c "End Headless Mode"
    exit
}
function Get-JanitorMode {
    # Use cli provided instructor name if present
    if ($instructorName) {
        $currentUser = $instructorName
    }
    else { 
        # this will use the cloudsdk account- typically used for daily testing
        $currentUser = gcloud auth list --format='value(account)' --filter=status=active
    }
    if (-not $currentUser) {
        Send-Update -t 2 -c "No google user authentication found.  It is illegal in 23 US states to continue without one.  Nice try though."
        Send-Update -t 2 -c "Run <gcloud auth login> and login with your work email."
        exit
    }
    # Make sure user isn't trying to run this as cloudsdk
    if ($currentUser.Contains("cloudsdk")) {
        Send-Update -t 2 -c "You're running as the HarnessEvents CloudSDK service account."
        Send-Update -t 2 -c "Switch to your work account with <gcloud config set account 'your email'>"
        exit
    }
    Set-Prefs -k "GoogleUser" -v $currentUser
    #$googleUser = "$($currentUser.split("@")[0])@harnessevents.io"
    Set-Prefs -k "InstructorEmail" -v "$($currentUser.split("@")[0])@harnessevents.io"
    if ($hourLimit) {
        $maxEventHours = $hourLimit
        $emailTarget = "notapplicable"
    }
    else {
        $maxEventHours = 1000000
        $emailTarget = $config.InstructorEmail
    }
    Send-Update -t 1 -c "Running event cleanup"
    $validEvents = @()
    $expiredOrgs = @()
    $validGCPProjects = @()
    $validAWSProjects = @()
    $validAzureProjects = @()
    Get-GoogleAccessToken
    # Load all open events
    $openEvents = gcloud storage ls gs://harnesseventsdata/events/open/*.json --verbosity=none
    foreach ($eventJson in $openEvents) {
        $e = gcloud storage cat $eventJson | ConvertFrom-Json
        if (-not $e.EventCreateTime) {
            $TimeDiff = 1000000
        }
        else {
            $TimeDiff = $(Get-Date) - $e.EventCreateTime
        }
        # if event is expired, mark it for removal
        if ($TimeDiff.TotalHours -gt $maxEventHours -or $e.GoogleUser -eq $emailTarget) {
            if ($emailTarget) {
                # Update based on matching email
                Send-Update -t 1 -c "Event $($e.GoogleEventName) is one of your events marked to remove."
            }
            else {
                Send-Update -t 1 -c "Event $($e.GoogleEventName) is $($TimeDiff.Totalhours)h old exceeding limit of $($maxEventHours)h."
            }
            if ($e.HarnessAccount -and $e.HarnessOrg -and $e.HarnessAccountId -and $e.HarnessPat -and $e.HarnessEnv) {
                $expiredOrgs += [PSCustomObject]@{
                    account = $e.HarnessAccount
                    org     = $e.HarnessOrg
                    id      = $e.HarnessAccountId
                    pat     = $e.HarnessPat
                    env     = $e.HarnessEnv
                }
                Send-Update -t 1 -c "Added $($e.HarnessOrg) in $($e.HarnessAccount) to expired events."
            }
            else {
                Send-Update -t 2 -c "Gross! One of these was missing- account: $($e.HarnessAccount) org: $($e.HarnessOrg) id: ($e.HarnessAccountId) pat: $($e.HarnessPat) env: $($e.HarnessEnv)"
            }
            gcloud storage mv $eventJson gs://harnesseventsdata/events/closed/$(Split-Path $eventJson -leaf)
        }
        else {
            # Event is still active- record it so we can wipe out any orphans later.
            # That sounded AWFUL.  jeez.  I meant DELETE any events that aren't ATTACHED to anything. #BanJediHateCrimes
            $validEvents += $e.GoogleEventEmail
            if ($e.GoogleProjectId) { $validGCPProjects += $e.GoogleProjectId }
            if ($e.AWSProjectId) { $validAWSProjects += $e.AWSProjectId }
            if ($e.AzureProjectId) { $validAzureProjects += $e.AzureProjectId }
            Send-Update -t 1 -c "$($e.GoogleEventEmail) is still valid with $([Math]::ROUND($maxEventHours - $TimeDiff.TotalHours,1))h remaining."
        }
    }
    Send-Update -t 1 "There are $($expiredOrgs.count) expired org(s) to process."
    Remove-HarnessEventDetails -accounts $expiredOrgs
    # Remove unattached google events
    $eventGroups = Get-UserGroups -allEvents
    Send-Update -t 1 -c "$($validEvents.count) valid / $($eventGroups.count) total events."
    foreach ($e in $eventGroups) {
        if ($validEvents -notcontains $e.email) {
            Send-Update -t 1 -c "$($e.email) is no longer valid."
            Remove-Event -email $e.email -id $e.id
        }
    }
    #Remove unattached google projects
    $gcpProjects = Get-GCPProjectList
    Send-Update -t 1 -c "$($validGCPProjects.count) valid / $($gcpProjects.count) total google project(s)."
    foreach ($project in $gcpProjects) {
        if ($validGCPProjects -notcontains $project.projectId) {
            Send-Update -t 1 -c "Removing project $($project.name) with google id $($project.projectId)"
            Remove-GCPProject -id $project.projectId
        }
    }
    if ($config.GoogleUser.contains("@harness.io")) {
        Send-Update -t 1 -c "Switching to original account" -r "gcloud config set account $($config.GoogleUser) --no-user-output-enabled"
    }
    if ($hourLimit) {
        Remove-HarnessEventsUsers
    }
    Send-Update -t 1 -c "End event cleanup" 
    exit
}

## Event Functions
function Add-UserToGroup {
    param (
        [Parameter(Mandatory = $true)][string] $userEmail,
        [Parameter(Mandatory = $true)][string] $groupEmail,
        [Parameter()][switch] $owner
    )
    # Retrieve group key
    $groupKey = Get-GroupKey -g $groupEmail
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
    Send-Update -t 1 -c "Checking on token"
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
    if ($config.CLIUser.contains("@harness.io")) {
        $initProject = gcloud projects list --filter='name:sales' --format=json | Convertfrom-Json
    }
    if ($config.CLIUser.contains("cloudsdk")) {
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
    # Get API token to access Google Drive and Google Sheets
    Get-GoogleApiAccessToken
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
function Get-GroupKey {
    # Google requires GroupKey for API calls- retrieve the key from the group name
    param (
        [string] $GroupEmail
    )
    $uri = "https://admin.googleapis.com/admin/directory/v1/groups?domain=harnessevents.io&query=email='$GroupEmail'"
    Send-Update -t 0 -c "Looking up key with uri: $uri"
    $response = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers
    if ($response.groups.id) {
        Send-Update -t 0 -c "Group ID retrieved: $($response.groups.id)"
        return $response.groups.id
    }
    else {
        Send-Update -t 2 -c "NO ID found for URI: $uri"
    }
}
function Get-GroupMembers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $groupEmail,
        [Parameter()]
        [switch] $splitIntoGroups # organize the results into owners/members and provide a count
    )
    # Retrieve group key - or use cached default if none provided
    $groupKey = Get-GroupKey -g $groupEmail
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
function Get-UserGroups {
    # Get all groups that a user belongs to
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $UserEmail,
        [Parameter()]
        [switch]
        $allEvents
    )
    if ($UserEmail) {
        $urlFilter = "&userKey=$UserEmail"
    }
    if ($allEvents) {
        $urlFilter = "&query=email:event-*"
    }
    $uri = "https://admin.googleapis.com/admin/directory/v1/groups?domain=harnessevents.io$urlFilter"
    Send-Update -t 0 -c "Getting Usergroups for uri: $uri"
    try {
        $response = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers
    }
    catch {
        Send-Update -t 2 -c "Oh, GOOOOD! : $($_.Exception.Message)"
        return $false
    }
    $response = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers
    return $response.groups
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
    Send-Update -t 0 -c "Create new group with uri: $uri"
    $response = Invoke-RestMethod -Method 'Post' -ContentType 'application/json' -Uri $uri -Body $body -Headers $headers
    Send-Update -t 0 -c "Create new group returned: $response"
    $success = $false
    $counter = 0
    Do {
        Send-Update -t 1 -c "Waiting for group creation..."
        $response = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers
        if ($response.groups) {
            Send-Update -t 1 -c "Group $email created successfully!"
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
}
function New-Event {
    Send-Update -t 1 -c "Creating new event"
    # Create instructor email for this user if it doesn't exist
    if (!(Get-User -u $config.InstructorEmail)) {
        New-User -u $config.InstructorEmail
        Send-Update -t 1 -c "Generated your instructor email: $($config.InstructorEmail)"  
    }
    # Create group if needed
    $uri = "https://admin.googleapis.com/admin/directory/v1/groups?domain=harnessevents.io&query=email='$($config.GoogleEventEmail)'"
    Send-Update -t 0 -c "Checking group email with uri: $uri"
    $response = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers
    if (!$response.groups) {
        Send-Update -t 0 -c "Group didn't exist. Creating."
        New-Group -e $config.GoogleEventEmail -n $config.GoogleEventName
        Add-UserToGroup -u $config.InstructorEmail -groupEmail $config.GoogleEventEmail -o | out-null
        Send-Update -t 1 -c "Waiting for $($config.InstructorEmail) to be registered as group owner"
        while (-not $groupReady) {
            # Wait until slow ass google registers the new group owner. zzzz.....
            $membershipCheck = (Get-UserGroups -u $config.InstructorEmail | Where-Object { $_.email -eq $config.GoogleEventEmail }).count
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
        Send-Update -t 1 -c "$($config.GoogleEventEmail) already exists.  Confirming ownership."
        $members = Get-GroupMembers -groupEmail $config.GoogleEventEmail -splitIntoGroups
        if (($members.owners.email | Where-Object { $_ -eq $config.GoogleEventEmail }).count -eq 1) {
            Send-Update -t 2 -c "This event is owned by: $($members.owners)- wait for the event to expire or contact the owner."
            exit
        }
        Send-Update -t 1 -c "Confirmed you are an event owner."
    }
    $eventId = Get-GroupKey -g $($config.GoogleEventEmail)
    Set-Prefs -k "GoogleEventId" -v $eventId
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
function Remove-Event {
    # V2 = splitting things up for headless mode refactor. leaving V1 for now for script mode
    # This version now only removes the event and user email
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $email,
        [Parameter(Mandatory = $true)]
        [string]
        $id
    )
    Get-GoogleAccessToken
    $script:HarnessFFHeaders = @{
        'x-api-key'    = $config.HarnessFFToken
        'Content-Type' = 'application/json'
    }
    Send-Update -t 1 -c "Deleting google event $email"
    $members = Get-GroupMembers -s -groupEmail $email
    foreach ($member in $members.members) {
        Remove-User -u $member.email
        Send-Update -t 1 -c "Deleted user: $($member.email)"
    }
    While ($memberCount -gt 0) {
        $memberCount = (Get-GroupMembers -s).memberCount
        Send-Update -t 1 -c "Waiting for delete confirmation for $memberCount accounts"
        Start-Sleep -s 4
        $memberCounter++
        if ($memberCounter -gt 20) {
            Send-Update -t 2 -c "Something went wrong- $eventEmail users didn't fully delete."
            exit
        }
    }
    Send-Update -t 0 -c "Successfully deleted users"
    $groupUri = "https://admin.googleapis.com/admin/directory/v1/groups/$($id)"
    $GroupCheckUri = "https://admin.googleapis.com/admin/directory/v1/groups?domain=harnessevents.io&query=email=$($email)"
    Send-Update -t 0 -c "Deleting group with uri: $groupUri"
    Invoke-RestMethod -Method 'Delete' -Uri $groupUri -Headers $headers | Out-null
    #Wait for group to be gone
    $counter = 0
    Do {
        $counter++
        if ($counter -ge 30) {
            Send-Update -t 2 -c "Deleting the google group took too long. I'm OUTTA here."
            exit
        }
        Send-Update -t 1 -c "Waiting for group deletion..."
        Send-Update -t 0 -c "Group exists uri: $groupCheckUri"
        $groupExists = Invoke-RestMethod -Method 'GET' -Uri $GroupCheckUri -Headers $headers
        Start-Sleep -s 3
    } until (-not $groupExists.groups)
}
function Sync-Event {
    Get-GoogleApiAccessToken
    #Get-Events
    if (-not $config.GoogleEventName) {
        Send-Update -t 2 -c "Please select a valid event"
        return
    }
    $script:HarnessHeaders = @{
        'x-api-key'    = $config.HarnessPAT
        'Content-Type' = 'application/json'
    }
    $script:HarnessFFHeaders = @{
        'x-api-key'    = $config.HarnessFFToken
        'Content-Type' = 'application/json'
    }
    #Confirm required values exist
    if (-not $config.GoogleEventName) {
        Send-Update -t 2 -c "Sorry, there must be a Google event configured."
        return
    }
    if (-not $config.HarnessPAT -or -not $config.HarnessAccountId -or -not $config.HarnessAccount) {
        Send-Update -t 2 -c "Sorry, a Harness token, AccountId, and Account Name are required to setup an event."
        return
    }
    if (-not $config.HarnessOrg) {
        Send-Update -t 2 -c "Sorry, a Harness Org name must be available before setting up an event."
        return
    }
    Add-EventUsers
    Add-HarnessEventDetails
    if ($config.UseGoogleClassroom) {
        New-GCP-Project
    }
    else {
        Remove-GCP-Project
    }
    Add-Variables
    Save-EventDetails
}

## Harness Functions
function Remove-HarnessEventDetails {
    [CmdletBinding()]
    param (
        [Parameter()]
        [object]
        $accounts #account, org, id, pat, env
    )
    foreach ($account in $accounts) {
        # Remove event users from Harness Account
        $HarnessHeaders = @{
            'x-api-key'    = $account.pat
            'Content-Type' = 'application/json'
        }
        $body = @{
            "searchTerm" = "harnessevents.io"
        } | ConvertTo-Json
        $userdetailsuri = "https://app.harness.io/ng/api/user/batch?accountIdentifier=$($account.id)&orgIdentifier=$($account.org)"
        $response = invoke-restmethod -uri $userdetailsuri -headers $HarnessHeaders -ContentType "application/json" -Method 'POST' -body $body
        $harnessUsers = $response.data.content | Where-Object { $_.email.Contains("@harnessevents.io") }
        #$eventUsers = (Get-GroupMembers -s).members
        foreach ($user in $harnessUsers) {
            $killuseruri = "https://app.harness.io/ng/api/user/$($user.uuid)?accountIdentifier=$($account.id)"
            invoke-restmethod -uri $killuseruri -headers $HarnessHeaders -ContentType "application/json" -Method 'DEL' | Out-Null
            Send-Update -t 1 -c "Removed $($user.email) from account $($account.id)"
        }
        if ($account.account -eq "HarnessEvents") {
            # Do specific things for HarnessEvents
            Send-Update -t 1 -c "Skipping flag 'after event' state since this is the common account"
            Send-Update -t 1 -c "Removing Harness org: $($account.org)"
            $uri = "https://app.harness.io/ng/api/organizations/$($account.org)?accountIdentifier=$($account.id)"
            Invoke-RestMethod -Method 'DEL' -headers $HarnessHeaders -uri $uri | Out-Null
        }
        else {
            Send-Update -t 2 -c "NEED TO REDO LOGIC HERE for V2 version of customer account org cleanup!"
            # $featureFlagsStart = Get-Content -path ./harnesseventsdata/config/featureflagsend.json | Convertfrom-Json
            # $currentFlags = Get-FeatureFlagStatus
            # $flagsNeeded = Compare-Object @($featureFlagsStart.PSObject.Properties) @($currentFlags.PSObject.Properties) -Property Name, Value | Where-Object { $_.SideIndicator -eq "<=" }
            # foreach ($flag in $flagsNeeded) {
            #     Update-FeatureFlag -flag $flag.Name -value $flag.Value
            # }
            # do {
            #     $currentFlags = Get-FeatureFlagStatus
            #     $flagsNeeded = Compare-Object @($featureFlagsStart.PSObject.Properties) @($currentFlags.PSObject.Properties) -Property Name, Value | Where-Object { $_.SideIndicator -eq "<=" }
            #     Send-Update -t 1 -c "Waiting for $($flagsNeeded.count) flag(s)..."
            #     Start-Sleep -s 2
            # } until (-not $flagsNeeded)
        }
    }
}
function Test-Connectivity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $harnessToken
    )
    Send-Update -t 1 -c "Starting Harness connectivity check"
    $harnessSplit = $harnessToken.split(".")
    if ($harnessSplit.count -ne 4) {
        Send-Update -t 3 -c "Harness Platform token was malformed."
    }
    $harnessAccount = $harnessSplit[1]
    $TestHarnessHeaders = @{
        "x-api-key" = $harnessToken
    }
    Send-Update -t 1 -c "Harness token..." -append
    $uri = "https://app.harness.io/ng/api/accounts/$harnessAccount"
    try {
        $response = Invoke-RestMethod -Method 'GET' -ContentType "application/json" -uri $uri -Headers $TestHarnessHeaders
    }
    catch {
        Send-Update -t 2 -c "Failed to connect to Harness API: $($_.Exception.Message)"
        return $false
    }
    Send-Update -t 1 -c "is valid."
    Set-Prefs -k "HarnessAccount" -v $response.data.companyName
    Set-Prefs -k "HarnessAccountId" -v $harnessAccount
    Set-Prefs -k "HarnessPAT" -v $harnessToken
    # OMG Why do 2 Harness API's use DIFFERENT strings to describe the SAME ENVIRONMENT *internal sobbing*
    $fixGodDamnEnv = $response.data.cluster.replace("-","")
    $correctEnv = $fixGodDamnEnv.substring(0,1).toUpper() + $fixGodDamnEnv.substring(1)
    if ($correctEnv -ne "Prod1") {
        Send-Update -t 2 "$correctEnv isn't the expected environment of Prod1 - just FYI if something doesn't work right."
    }
    Set-Prefs -k "HarnessEnv" -v $correctEnv
    return $response
}

## Classroom functions
function Get-GCPProjectList {
    # Retrieve administration organization
    $adminOrg = invoke-expression -Command "gcloud organizations list --filter='display_name:harnessevents.io' --format=json" | Convertfrom-Json
    $adminOrgId = $adminOrg.name.split("/")[1]
    Set-Prefs -k "AdminOrgId" -v $adminOrgId
    # Retrieve all child projects except administration
    $projects = Send-Update -t 1 -c "Retrieving projects" -r "gcloud projects list --filter='parent.id:$($config.AdminOrgId) AND -name:administration' --format=json" | Convertfrom-Json
    return $projects
}
function New-GCPProject {
    if ($googleCloudProjectOverride) {
        Set-Prefs -k "GoogleProjectId" -v $googleCloudProjectOverride
        Set-Prefs -k "GoogleProject" -v "Command Line Override"
        Set-Prefs -k "GoogleRegion" -v "us-central1"
        $projectCheck = Send-Update -t 1 -c "Check Project Override exists" -r "gcloud projects list --filter='id:$($config.GoogleProjectId)' --format=json" | convertfrom-json
    }
    else {
        # Use Harness Org as the project name- adjusting for the different character requirements *insert massive eyeroll here*
        Set-Prefs -k "GoogleProject" -v $config.HarnessOrg.replace("_","-")
        $projectCheck = Send-Update -t 1 -c "Check for existing project" -r "gcloud projects list --filter='name:$($config.GoogleProject)' --format=json" | convertfrom-json
    }
    if ($googleCloudProjectOverride -and -not $projectCheck) {
        Send-Update -t 2 -c "Google project override used but $googleCloudProjectOverride doesn't exist. BYIIEEEEE."
        exit
    }
    if ($projectCheck) {
        # Project already exists- skip creation
        Send-Update -t 1 -c "Project already exists- skipping creation."
        Set-Prefs -k "GoogleProjectId" -v $projectCheck.projectId
    }
    else {
        # Get organization of admin project to assign to new project
        $googleAdminAncestors = Send-Update -t 1 -c "Retrieve org info" -r "gcloud projects get-ancestors $($config.AdminProjectId) --format=json" | ConvertFrom-Json
        $GoogleOrgId = ($googleAdminAncestors | Where-Object { $_.type -eq "organization" }).id
        # Get billing project of admin project to associate with this project
        $AdminProjectInfo = Send-Update -t 1 -c "Retrieving billing account" -r "gcloud billing accounts list --filter=displayName='HarnessEvents' --format=json" | ConvertFrom-Json
        $GoogleBillingProject = $AdminProjectInfo.name.split("/")[1]
        # Generate a unique project ID following all of Google's goofy rules
        if ($GoogleProject.length -gt 16) {
            Set-Prefs -k "GoogleProject" -v $config.GoogleProject.substring(0,16)
        }
        $projectID = "event-$(Get-Randomstring)"
        $projectID = $projectID.tolower()
        Send-Update -t 1 -o -c "Create $($config.GoogleProject) project" -r "gcloud projects create $projectID --name=""$($config.GoogleProject)"" --organization=$GoogleOrgId --set-as-default -q"
        while (-not $projectDetails) {
            $projectDetails = Send-Update -t 1 -c "Waiting for project to be available..." -r "gcloud projects list --filter='name:$($config.GoogleProject)' --format=json" | Convertfrom-Json   
            Start-Sleep -s 6
        }
        # Associate project with billing account
        Send-Update -t 1 -o -c "Associate billing account" -r "gcloud billing projects link $projectID --billing-account=$GoogleBillingProject"
        Set-Prefs -k "GoogleProjectId" -v $projectDetails.projectId
        # Add users to project
        Send-Update -t 1 -o -c "Add group 300@harnessevents.io to project" -r "gcloud projects add-iam-policy-binding $($config.GoogleProjectId) --member='group:300@harnessevents.io' --role='roles/owner' -q" | out-null
        Send-Update -t 1 -o -c "Add group 300@harnessevents.io to project" -r "gcloud projects add-iam-policy-binding $($config.GoogleProjectId) --member='user:$($config.InstructorEmail)' --role='roles/owner' -q" | out-null
        Send-Update -t 1 -o -c "Add group $($config.GoogleEventEmail) to project" -r "gcloud projects add-iam-policy-binding $($config.GoogleProjectId) --member='group:$($config.GoogleEventEmail)' --role='roles/editor' -q" | out-null
        # Enable API's needed for events
        $projectAPIs = @("compute.googleapis.com","container.googleapis.com","run.googleapis.com")
        Foreach ($api in $projectApis) {
            send-Update -t 1 -o -c "Enabling $api API" -r "gcloud services enable $api"
        }
        # Wait for confirmation that API's are enabled
        $counter = 0
        Do {
            $counter++
            if ($counter -ge 10) {
                Send-Update -t 2 -c "It took too long enabling needed API's"
            }
            $enabledAPIs = gcloud services list --format=json | Convertfrom-Json
            $neededAPIs = Compare-Object $projectAPIs $enabledAPIs.config.name | Where-Object { $_.SideIndicator -eq "<=" }
            Start-Sleep -s 2
        } until (-not $neededAPis)
        # Create worker, get keys, add to IAM
        Send-Update -t 1 -o -c "Create service account" -r "gcloud iam service-accounts create worker1"
        Send-Update -t 1 -o -c "Grant service account permissions" -r "gcloud projects add-iam-policy-binding $($config.GoogleProjectId) --member=serviceAccount:worker1@$($config.GoogleProjectId).iam.gserviceaccount.com --role='roles/editor'"
        Send-Update -t 1 -o -c "Generate local key json file" -r "gcloud iam service-accounts keys create worker1.json --iam-account=worker1@$($config.GoogleProjectId).iam.gserviceaccount.com"
        Add-SecretJson -fileName worker1.json -id GCP_Service_Account
    }
    if (Test-Path worker1.json) { Remove-Item worker1.json }
    # Load GCP-specific templates
    Add-OrgYaml -YamlFolder ./harnesseventsdata/orgGCP
    # Move on to loading GCP resources
    New-GCPResources
}
function New-GCPResources {
    # Create unique Google Resource ID (this will be harnessevents normally, but creates a unique ID if shared environment)
    if ($googleCloudProjectOverride) {
        # We're building this cluster in a potentially shared space- use the current user as an indentifier
        $cleanIdentifier = "-$($config.GoogleUser.split('@')[0].replace('.',''))"
        $clusterRegion = "us-central1"
    }
    else {
        $clusterRegion = Send-Update -t 1 -c "Getting first available region" -r "gcloud compute regions list --filter='name:us-*' --limit=1 --format='value(NAME)' --verbosity=error --project=$($config.GoogleProjectId)"
    }
    # Save the identifier/region used here for fun activities later
    Set-Prefs -k "GoogleResourceID" -v "harnessevent$cleanIdentifier"
    Set-Prefs -k "GoogleRegion" -v "$clusterRegion"
    # Create cluster if needed
    $clusterExists = Send-Update -t 1 -c "Check for Google harnessevent cluster" -r "gcloud container clusters list --filter=name=$($config.GoogleResourceID) --format=json  --verbosity=error --project=$($config.GoogleProjectId)" | Convertfrom-Json
    if (-not $clusterExists) {
        Send-Update -t 1 -c "Create kubernetes cluster" -r "gcloud container clusters create $($config.GoogleResourceID) -m e2-standard-4 --num-nodes=1 --zone=$clusterRegion --no-enable-insecure-kubelet-readonly-port --scopes=cloud-platform  --project=$($config.GoogleProjectid)"
        $clusterExists = Send-Update -t 1 -c "Confirm cluster exists" -r "gcloud container clusters list --filter=name=$($config.GoogleResourceID) --format=json --project=$($config.GoogleProjectId)" | Convertfrom-Json
        if (-not $clusterExists) {
            Send-Update -t 2 -c "Attempted to create google kubernetes cluster it failed.  IT FAILED SO BAD. WHY?  WHYYYYYY GOOGLE?"
            exit
        }
    }
    Send-Update -t 1 -o -c "Retrieve kubernetes credentials" -r "gcloud container clusters get-credentials $($config.GoogleResourceID) --zone=$clusterRegion  --project=$($config.GoogleProjectId)"  
    Add-Delegate -delegatePrefix "gcp"
    # Create google artifact registry if needed
    $registryExists = Send-Update -t 1 -c "Check if Artifact Registry exists" -r "gcloud artifacts repositories list --filter=$($config.GoogleResourceID) --project=$($config.GoogleProjectId) --format=json" | Convertfrom-Json
    if ($registryExists) {
        Send-Update -t 0 -c "Registry exists- skipping create"
    }
    else {
        # Create Google artifact registry
        Send-Update -t 1 -c "Create google artifact registry" -r "gcloud artifacts repositories create $($config.GoogleResourceID) --repository-format=docker --location=$($config.GoogleRegion) --project=$($config.GoogleProjectId)"
    }
}
function Remove-GCPProject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $id
    )
    Send-Update -t 1 -o -c "Removing Google Project" -r "gcloud projects delete $id --quiet"
    $Counter = 0
    Do {
        $counter++
        if ($counter -ge 10) {
            Send-Update -t 2 -c "Wow, something went terrrrrrribly wrong trying to remove Google Project: $id"
            exit
        }
        $projectCheck = Send-Update -t 1 -c "Waiting for project delete confirmation..." -r "gcloud projects list --filter='name:$id' --format=json" | convertfrom-json
        Start-Sleep -s 5
    } while ($projectCheck)
}

## Main
Test-PreFlight
Get-Prefs($Myinvocation.MyCommand.Source)
switch ($action) {
    "create" { Get-HeadlessMode }
    "remove" { Get-JanitorMode }
    Default { Get-Help }
}
