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
    #Get-GoogleAccessToken
    #New-Event
    #Test-Connectivity -harnessToken $config.HarnessEventsPAT | Out-Null
    #Sync-Event
    if ($config.GoogleUser.contains("@harness.io")) {
        Send-Update -t 1 -c "Switching to original account" -r "gcloud config set account $($config.GoogleUser) --no-user-output-enabled"
    }
    Send-Update -t 1 -c "End Headless Mode"
    exit
}

## Event Functions
function New-Event {
    # Requires config set for: EventName
    # while (-not $nameselected) {
    #     if ($config.EventName) {
    #         $newEvent = $config.EventName
    #     }
    #     else {
    #         $newEvent = read-host -prompt "Name for new event? (lower characters only) to abort"
    #     }
    #     if (-not($newEvent)) {
    #         return
    #     }
    # Add an instructor email for this user
    if (!(Get-User -u $config.InstructorEmail)) {
        New-User -u $config.InstructorEmail
        Send-Update -t 1 -c "Generated your instructor email: $($config.InstructorEmail)"  
    }
    # $eventName = $newEvent -replace '\W', ''
    # $eventName = "event-" + $eventName.tolower()
    # $newEmail = $eventName + "@harnessevents.io"
    # Send-Update -t 0 -c "Generated email: $newEmail from value $newEvent"
    # Check if name is in use
    $uri = "https://admin.googleapis.com/admin/directory/v1/groups?domain=harnessevents.io&query=email='$($config.EventEmail)'"
    Send-Update -t 0 -c "Checking group email with uri: $uri"
    $response = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers
    if (!$response.groups) {
        # Group doesn't exist
        New-Group -e $newEmail -n $eventName
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
        $nameselected = $newEmail
    }
    else {
        Send-Update -t 2 -c "Event email already used: $newEmail"
        if ($config.EventName -eq "deploytest") {
            # Need to get this even if about to fail so removal works
            $eventId = Get-GroupKey -g $newEmail
            Set-Prefs -k "GoogleEventId" -v $eventId
            Set-Prefs -k "GoogleEventEmail" -v $newEmail
            Send-Update -t 2 -c "Previous automated test did not successfully delete event email: $newEmail"
            Exit 1
        }
        if ($config.EventName) {
            $nameselected = $newEmail
        }
    }
    # }
    $eventId = Get-GroupKey -g $nameselected
    Set-Prefs -k "GoogleEventId" -v $eventId
    Get-Events
}

## Main
Test-PreFlight
Get-Prefs($Myinvocation.MyCommand.Source)
switch ($action) {
    "create" { Get-HeadlessMode }
    "remove" {}
    Default { Get-Help }
}
