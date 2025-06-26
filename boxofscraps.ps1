# VSCODE: ctrl/cmd+k+1 folds all functions, ctrl/cmd+k+j unfold all functions. Check '.vscode/launch.json' for any current parameters
param (
    [switch] $help, # show other command options and exit
    [switch] $verbose, # default output level is 1 (info/errors), use -v for level 0 (debug/info/errors)
    [switch] $cloudCommands, # FORCED ON!! enable to show commands
    [switch] $logReset, # enable to reset log between runs
    [int] $users, # Users to create, switches to multiuser mode
    [string] $network, # Specify cloudformation stack in AWS (vs default group 'scw-AWSStack')
    [switch] $aws, # use aws
    [switch] $azure, # use azure
    [switch] $gcp, # use gcp
    [switch] $multiUserMode #Switch to classroom setup for x users
)

# Core Functions
function Get-UserName {
    # Generate a new username
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
    if ($run -and $outputSuppression) { return invoke-expression $run 1>$null }
    if ($run) { return invoke-expression $run }
}
function Get-Prefs($scriptPath) {
    # Do the things for the command line switches selected
    if ($help) { Get-Help }
    if ($verbose) { $script:outputLevel = 0 } else { $script:outputLevel = 1 }
    if ($cloudCommands) { $script:showCommands = $true } else { $script:showCommands = $true }
    if ($logReset) { $script:retainLog = $false } else { $script:retainLog = $true }
    if ($aws) { $script:useAWS = $true }
    if ($azure -eq $true) { $script:useAzure = $true }
    if ($gcp) { $script:useGCP = $true }
    if ($multiUserMode) { $script:multiUserMode = $true }
    # If no cloud selected, use all
    if ((-not $useAWS) -and (-not $useAzure) -and (-not $useGCP)) { $script:useAWS = $true; $script:useAzure = $true; $script:useGCP = $true }
    # Set Script level variables and housekeeping stuffs
    [System.Collections.ArrayList]$script:eventList = @()
    [System.Collections.ArrayList]$script:choices = @()
    $script:currentLogEntry = $null
    $script:muCreateClusters = $false
    $script:muCreateWebApp = $false
    $script:muDeployDynatrace = $false
    # Any yaml here will be available for installation- file should be namespace (i.e. x.yaml = x namescape)
    $script:yamlList = @("https://raw.githubusercontent.com/suchcodewow/dbic/main/deploy/dbic",
        "https://raw.githubusercontent.com/suchcodewow/bobbleneers/main/bnos" )
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
    # Load preferences/settings.  Access with $config variable anywhere.  Set-Prefs automatically updates $config variable and saves to file
    # Set with Set-Prefs function
    if ($scriptPath) {
        $script:configFile = "$scriptPath.conf"
        if (Test-Path $configFile) {
            Send-Update -c "Reading config" -t 0
            $script:config = Get-Content $configFile -Raw | ConvertFrom-Json
        }
        else {
            $script:config = [PSCustomObject]@{}
            #$config["schemaVersion"] = "2.0"
            if ($MyInvocation.MyCommand.Name) {
                $config | ConvertTo-Json | Out-File $configFile
                Send-Update -c "CREATED config" -t 0
            }
        }
    }
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
function Get-Choice() {
    # Present list of options and get selection
    write-output $choices | sort-object -property Option | format-table $choiceColumns | Out-Host
    $cmd_selected = read-host -prompt "Which option to execute? [<enter> to quit]"
    if (-not($cmd_selected)) {

        write-host "buh bye!`r`n" | Out-Host
        exit
    }
    if ($cmd_selected -eq 0) { Get-Quote }
    return $choices | Where-Object { $_.Option -eq $cmd_selected } | Select-Object -first 1 
}
function Add-Choice() {
    #Add a choice to main menu for user selection
    param(
        [string] $key, # key identifying this choice, unique only
        [string] $description, # description of item
        [string] $current, # current selection of item, if applicable
        [string] $function, # function name to call if changing item
        [object] $parameters, # parameters needed in the function
        [switch] $todo # recommend this option if it's the first one with a blank current value
    )
    Send-Update -c "Add choice: $key" -t 0
    # If this key exists, delete it and anything that followed
    $keyOption = $choices | Where-Object { $_.key -eq $key } | select-object -expandProperty Option -first 1
    if ($keyOption) {
        $staleOptions = $choices | Where-Object { $_.Option -ge $keyOption }
        $staleOptions | foreach-object { Send-Update -c "Removing $($_.Option) $($_.key)" -t 0; $choices.remove($_) }
    }
    # Add todo flag if switch used
    $todoIndicator = "<----TODO"
    $existingTodo = $choices | Where-Object { $_.current -eq $todoIndicator }
    if ($todo -and -not $existingTodo -and -not $current) {
        $current = $todoIndicator
    }
    $choice = New-Object PSCustomObject -Property @{
        Option         = $choices.count + 1
        key            = $key
        description    = $description
        current        = $current
        callFunction   = $function
        callProperties = $parameters
        

    }
    [void]$choices.add($choice)
}
function Test-PreFlight {
    if (Get-Command gcloud -ErrorAction SilentlyContinue) {
        Send-Update -t 1 -c "gcloud commands available!"
    }
    else {
        Send-Update -t 2 -c "gcloud commands not found. install via mac with: brew install --cask google-cloud-sdk"
        Exit-PSHostProcess
    }
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

# Event Functions
function New-Event {
    # Add new event (essentially a google group with attached email)
    Get-GoogleAccessToken
    while (-not $nameselected) {
        $newEvent = read-host -prompt "Name for new event? (lower characters only) <enter> to abort"
        if (-not($newEvent)) {
            return
        }
        $eventName = $newEvent -replace '\W', ''
        $eventName = $eventName.tolower()
        $newEmail = "event-" + $eventName + "@harnessevents.io"
        Send-Update -t 0 -c "Generated email: $newEmail from value $newEvent"
        # Check if name is in use
        $uri = "https://admin.googleapis.com/admin/directory/v1/groups?domain=harnessevents.io&query=email='$newEmail'"
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
                    Start-Sleep -s 3
                }
            }
            Send-Update -t 1 -c "Successfully added user: $($config.InstructorEmail) as owner."
            $nameselected = $newEmail
        }
        else {
            Send-Update -t 2 -c "Sorry, event email already used: $newEmail"
        }
    }
    Get-Events
}
function Add-Event {
    param(
        [string] $n, # name of item
        [string] $i, # item unique identifier
        [switch] $d, # [$true/$false] default option
        [string] $e # group email
    )
    $eventItem = New-Object PSCustomObject -Property @{
        Name    = $n
        ID      = $i
        default = $d
        email   = $e
        option  = $eventList.count + 1
    }
    [void]$eventList.add($eventItem)
}
function Add-EventUsers {
    # Ask how many users are needed
    while (-not $usersToAdd) {
        $userCount = read-host -prompt "How many users to add to $($config.GoogleEventName)? <enter> to abort"
        if (-not($userCount)) {
            return
        }
        if ($userCount -match '^[0-9]+$') {
            $usersToAdd = $userCount
        }
        else {
            Send-Update -t 2 -c "Whoa bud, howbow a number there for quantity of user?"
        }
    }
    $counter = 1
    Get-GoogleAccessToken
    # Get current total
    $startingCount = (Get-GroupMembers -s).memberCount
    $totalCount = $startingCount + $userCount
    Send-Update -t 1 -c "Group has $startingCount now with goal of $totalCount"
    # Loop to add users
    while ($counter -le $userCount) {
        $newUser = $false
        While (-not $newUser) {
            $user = Get-UserName
            $response = Get-User -u $user
            if ($response) {
                # username taken, try again. Thanks, RND!
            }
            else {
                # username is good- add the user then add user to group
                New-User -user "$user@harnessevents.io" | Out-null
                Add-UserToGroup -user "$user@harnessevents.io" | out-null
                Send-Update -t 1 -c "Added user: $user@harnessevents.io"
                $newUser = $true
            }
        }
        $counter++
    }
    Set-Prefs -k "projectsCreated"
    Send-Update -t 1 -c "Waiting for all users to be available..."
    $memberCounter = 0
    While ($memberCount -lt $totalCount) {
        $memberCount = (Get-GroupMembers -s).memberCount
        Send-Update -t 1 -c "$memberCount of $totalCount"
        Start-Sleep -s 4
        $memberCounter++
        if ($memberCounter -gt 20) {
            Send-Update -t 2 -c "Something went wrong- users didn't load correctly."
            exit
        }
    }
    Send-Update -t 1 -c "All users added successfully"
    Get-Events
}
function Get-Events {
    # Check token status/refresh
    Get-GoogleAccessTokenV2
    # Create an instructor email account if needed
    if (!(Get-User -u $config.InstructorEmail)) {
        New-User -u $config.InstructorEmail
        Send-Update -t 1 -c "Generated your instructor email: $($config.InstructorEmail)"  
    }
    else {
        #Send-Update -t 1 -c "Your existing instructor email is: $($config.InstructorEmail)"
    }
    # Create/Clear event list
    $eventList.Clear()
    # Get groups for current user
    $currentGroups = Get-UserGroups -u $($config.InstructorEmail)
    foreach ($group in $currentGroups) {
        # Filter to event groups only
        if ($group.email.length -ge 5) {
            if ($group.email.substring(0,6) -eq "event-") {
                $Params = @{}
                if ($group.id -eq $config.GoogleEventId) { $Params['d'] = $true }
                Add-Event @Params -n $group.name -i $group.id -e $group.email
                Send-Update -t 0 -c "Found event email: $($group.email)"
            }
        }
    }
    # Provide option to create a new event
    Add-Event -n "+new event" -i "_create"
    # Always provide option to change events
    Add-Choice -k "EVENT" -d "Create/Switch/Join Event" -c $($config.GoogleEventName) -f "Set-Event" -todo
    #Add-Choice -k "RESETPW" -d "Reset instructor email" -c $config.InstructorEmail -f "Reset-Password"
    $eventDefault = $eventList | Where-Object default -eq $true
    if ($eventDefault.count -eq 1) {
        Send-Update -t 0 -c "Setting event with default:  $eventDefault"
        Set-Event -p $eventDefault
    }
}
function Set-Event {
    param(
        [object] $preset # optional preset to bypass selection
    )
    $eventSelected = $preset
    #Prompt for event option
    while (-not $eventSelected) {
        write-output $eventList | sort-object -property Option | format-table $eventColumns | Out-Host
        $newEvent = read-host -prompt "Select existing or create new event? <enter> to abort"
        if (-not($newEvent)) {
            return
        }
        $eventSelected = $eventList | Where-Object { $_.Option -eq $newEvent } | Select-Object -first 1
        if (-not $eventSelected) {
            write-host -ForegroundColor red "`r`nY U no pick valid option?" 
        }
    }
    if ($eventSelected.id -eq "_create") {
        # Create new event then reload options
        New-Event
    }
    else {
        # Cache choice details
        Set-Prefs -k "GoogleEventName" -v $eventSelected.name
        Set-Prefs -k "GoogleEventId" -v $eventSelected.id
        Set-Prefs -k "GoogleEventEmail" -v $eventSelected.email
        # And reset harness config assuming this new event uses a different account and not preset
        if (-not $preset) {
            Set-Prefs -k "HarnessAccount"
            Set-Prefs -k "HarnessAccountId"
            Set-Prefs -k "HarnessPAT"
        }
        $memberCount = Get-GroupMembers -s
        # Add option to change event later
        Add-Choice -k "ADDUSERS" -d "Add event attendees" -c "$($memberCount.memberCount) attendee(s)" -f "Add-EventUsers"
        Add-Choice -k "GETDETAILS" -d "Save event details" -c "$($membercount.ownerCount) instructor(s)" -f "Get-EventDetails"
        Add-Choice -k "DELEVENT" -d "Delete event & all classrooms" -f "Remove-Event"
        Get-HarnessConfiguration
    }
}
function Get-EventDetails {
    $members = Get-GroupMembers | select-object -property role, email | sort-object -property role -Des
    $members | Add-Member -MemberType NoteProperty -Name "password" -Value ""
    foreach ($member in $members) {
        if ($member.role -eq "MEMBER") {
            $member.role = "Attendee"
            $member.password = "Harness!"
        }
        else {
            $member.role = "Instructor"
        }
    }
    $members | Format-Table
    $members | Export-Csv "$($config.GoogleEventName).csv"
    Send-Update -t 1 -c "Exported --> $($config.GoogleEventName).csv"
}
function Remove-Event {
    $confirm = Read-Host -prompt "Confirm you want to remove event: $($config.GoogleEventName)? <y for yes>"
    If ($confirm -ne "y") {
        return
    }
    Send-Update -t 1 -c "Deleting Users"
    $members = Get-GroupMembers -s
    foreach ($member in $members.members) {
        Remove-User -u $member.email
        Send-Update -t 1 -c "Deleted user: $($member.email)"
    }
    While ($memberCount -gt 0) {
        $memberCount = (Get-GroupMembers -s).memberCount
        Send-Update -t 1 -c "$memberCount remaining"
        Start-Sleep -s 4
        $memberCounter++
        if ($memberCounter -gt 20) {
            Send-Update -t 2 -c "Something went wrong- users didn't delete."
            exit
        }
    }
    Send-Update -t 1 -c "Successfully deleted users"
    $groupUri = "https://admin.googleapis.com/admin/directory/v1/groups/$($config.GoogleEventId)"
    Invoke-RestMethod -Method 'Delete' -Uri $groupUri -Headers $headers
    Send-Update -t 1 -c "Deleted event: $($config.GoogleEventName)"
    Set-Prefs -k "GoogleEventEmail"
    Set-Prefs -k "GoogleEventId"
    Set-Prefs -k "GoogleEventName"
    Get-Events
}

# Google Login Functions
function Get-GoogleLogin {
    $myGoogleAccount = Send-Update -t 1 -c "Retrieving local accounts" -r "gcloud auth list --filter=account:'harness.io' --format='value(account)'"
    if ($myGoogleAccount.count -eq 1) {
        Send-Update -t 1 -c "Using current account" -r "gcloud config set account $myGoogleAccount  --no-user-output-enabled"
        $currentUser = $myGoogleAccount
    }
    Add-Choice -k "GOOGLEUSER" -d "Login/Change Google Account" -c $currentUser -f "Set-GoogleLogin" -t
    if ($currentUser) {
        Send-Update -t 1 -c "Using existing email: $currentUser"
        Set-GoogleLogin -p $currentUser
    }
}
function Set-GoogleLogin {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $preset
    )
    if ($preset) {
        $currentUser = $preset
    }
    else {
        Send-Update -t 1 -c "Opening login page..." -r "gcloud auth login"
    }
    $currentUser = Send-Update -t 0 -c "Confirming Login" -r "gcloud auth list --filter=status:ACTIVE --format='value(account)'"
    if (-not $currentUser) { return } else {
        Set-Prefs -k "GoogleUser" -v $currentUser
        # Add an instructor email as well
        Set-Prefs -k "InstructorEmail" -v "$($currentUser.split("@")[0])@harnessevents.io"
        Get-Events
    }
}
function Get-GoogleAccessToken {
    # Check for valid token
    if ($config.GoogleAccessToken -and $config.GoogleAccessTokenTimestamp) {
        # Check if token is over 50m old
        $TimeDiff = $(Get-Date) - $config.GoogleAccessTokenTimestamp
        if ($TimeDiff.TotalMinutes -lt 50) {
            Send-Update -t 0 -c "Google Workspace Token age is OK: $([math]::round($TimeDiff.TotalMinutes))m."
            $script:headers = @{
                "Authorization" = "Bearer $($config.GoogleAccessToken)"
            }
            return
        }
        else {
            Send-Update -t 1 -c "Google Workspace Token is too old: $([math]::round($TimeDiff.TotalMinutes))m."
        }
    }
    else {
        Send-Update -t 1 -c "Token or timestemp missing."
    }
    # Refresh token
    Send-Update -t 1 -c "Refreshing token."
    Get-AccessKeys
    $Scope = "https://www.googleapis.com/auth/admin.directory.user https://www.googleapis.com/auth/admin.directory.group"
    $accessToken = $null
    # arbitrary port number to listen on
    $port = 12005
    # client identifier of your application configured in the Google Console
    $clientId = $($config.tom1)
    # client secret of your application configured in the Google Console
    $clientSecret = $($config.jerry1)
    # URL used to obtain start an OAuth authorization flow
    $url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=$clientId&redirect_uri=http://localhost:$port&response_type=code&scope=$Scope&setLoginHint=$($config.GoogleUser)"
    # Kick off the default web browser
    Start-Process $url
    # Spin up our .NET Core 3.0 application hostig the web server
    #$authorizationCode = & dotnet run -p .\OAuthListener -- $port
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://localhost:$port/")
    $listener.Start()
    Send-Update -t 1 -c "Setup listener on port $port"

    #Wait for listener to catch a response
    $context = $listener.getContext()
    $authorizationCode = $context.Request.QueryString["code"]

    #Write out response to user
    $webPageResponse = "<html><body><div>Safe to close window </div></body></html>"
    $webPageResponseEncoded = [System.Text.Encoding]::UTF8.GetBytes($webPageResponse)
    $webPageResponseLength = $webPageResponseEncoded.Length
    $response = $context.response
    $response.ContentLength64 = $webPageResponseLength
    $response.ContentType = "text/html; charset=UTF-8"
    $response.OutputStream.Write($webPageResponseEncoded, 0, $webPageResponseLength)
    $response.OutputStream.Close()

    # if an authorization code was written to stdout then
    # exchange it for an access token, otherwise output an error
    if ($authorizationCode) {
        $authorizationResponse = Invoke-RestMethod -Uri "https://www.googleapis.com/oauth2/v4/token?code=$authorizationCode&client_id=$clientId&client_secret=$clientSecret&redirect_uri=http://localhost:$port&grant_type=authorization_code" -Method Post
        $accessToken = $authorizationResponse.access_token
        $currentUser = gcloud auth list --filter=status:ACTIVE --format="value(account)"
        Set-Prefs -k "GoogleAccessToken" -v $accessToken
        Set-Prefs -k "GoogleAccessTokenTimestamp" -v $(Get-date)
        Set-Prefs -k "GoogleUser" -v $currentUser
        $script:headers = @{
            "Authorization" = "Bearer $($config.GoogleAccessToken)"
        }
        Send-Update -t 1 -c "Successfully retrieved a new token and timestamp."

    }
    else {
        Send-Update -t 2 -c "Unexpected error while retrieving access token."
    }
}
function Get-GoogleAccessTokenV2 {
    # Check for valid token
    if ($config.GoogleAccessToken -and $config.GoogleAccessTokenTimestamp) {
        # Check if token is over 50m old
        $TimeDiff = $(Get-Date) - $config.GoogleAccessTokenTimestamp
        if ($TimeDiff.TotalMinutes -lt 30) {
            Send-Update -t 0 -c "Google Workspace Token age is OK: $([math]::round($TimeDiff.TotalMinutes))m."
            $script:headers = @{
                "Authorization" = "Bearer $($config.GoogleAccessToken)"
            }
            return
        }
        else {
            Send-Update -t 1 -c "Google Workspace Token is too old: $([math]::round($TimeDiff.TotalMinutes))m."
        }
    }
    else {
        Send-Update -t 1 -c "Token or timestemp missing."
    }
    # Refresh token
    Send-Update -t 1 -c "Refreshing token"
    $project = gcloud projects list --filter='name:administration' --format=json | Convertfrom-Json
    if ($project.count -ne 1) {
        Send-Update -t 2 -c "Failed to find project. Try running (gcloud auth login) using your work email."
        exit
    }
    Set-Prefs -k "AdminProjectId" -v $($project.projectId)
    Send-Update -t 1 -c "Retrieving credentials" -r "gcloud secrets versions access latest --secret='HarnessEventsAccount' --project=$($config.AdminProjectId)" | Out-File -FilePath harnessevents.json
    if (!(Test-Path("harnessevents.json"))) {
        Send-Update -t 2 -c "HarnessEventsAccount not found. You might need to run 'gcloud auth login' again with your work email."
        exit
    }
    # Sneak in grabbing the Harness Feature Flag token even though this is a google function. shhhhh!
    if (-not $config.HarnessFFToken) {
        $HarnessFFToken = Send-Update -t 1 -c "Retrieving credentials" -r "gcloud secrets versions access latest --secret='HarnessEventsFF' --project=$($config.AdminProjectId)" 
        Set-Prefs -k "HarnessFFToken" -v $HarnessFFToken
    }
    Send-Update -t 1 -c "Activating service account" -r "gcloud auth activate-service-account --key-file=harnessevents.json --no-user-output-enabled"
    $authorizationCode = Send-Update -t 1 -c "Retrieving account token" -r "gcloud auth print-access-token --scopes='https://www.googleapis.com/auth/admin.directory.user https://www.googleapis.com/auth/admin.directory.group'"
    if ($authorizationCode) {
        # Save valid token
        Set-Prefs -k "GoogleAccessToken" -v $authorizationCode
        Set-Prefs -k "GoogleAccessTokenTimestamp" -v $(Get-date)
        # Save the name of the google account to use later
        $googleServiceAccount = gcloud auth list --filter=status:ACTIVE --format='value(account)'
        Set-Prefs -k "GoogleServiceAccount" -v $googleServiceAccount
        $script:headers = @{
            "Authorization" = "Bearer $($config.GoogleAccessToken)"
        }
        Send-Update -t 0 -c "Successfully retrieved a new token and timestamp."

    }
    else {
        Send-Update -t 2 -c "Unexpected error while retrieving access token."
    }
    Send-Update -t 1 -c "Switching to original account" -r "gcloud config set account $($config.GoogleUser) --no-user-output-enabled"
}
function Get-AccessKeys {
    $project = gcloud projects list --filter='name:administration' --format=json | Convertfrom-Json
    if ($project.count -ne 1) {
        Send-Update -t 2 -c "Failed to find admin project. Might need to login (gcloud auth login)"
        exit
    }
    Set-Prefs -k "AdminProjectId" -v $($project.projectId)
    gcloud config set project $($config.AdminProjectId)
    $tom1 = gcloud secrets versions access latest --secret="tom1" --project=$($config.AdminProjectId)
    if (!$tom1) {
        Send-Update -t 2 -c "tom1 not found."
        exit
    }
    Set-Prefs -k "tom1" -v $tom1
    $jerry1 = gcloud secrets versions access latest --secret="jerry1" --project=$($config.AdminProjectId)
    if (!$jerry1) {
        Send-Update -t 2 -c "jerry1 not found."
        exit
    }
    Set-Prefs -k "jerry1" -v $jerry1
    Send-Update -t 1 -c "Projects and administration access loaded successfully"
}

# Google Workspace Functions
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
        Send-Update -t 2 -c "Group Key is missing!  Cannot proceed"
        exit
    }
    # Build api call for group
    $uri = "https://admin.googleapis.com/admin/directory/v1/groups/$groupKey/members"
    Send-Update -t 0 -c "Group URI: $uri"
    if ($owner) { $role = "OWNER" } else { $role = "MEMBER" }
    $body = @{
        "email" = $userEmail
        "role"  = $role
    } | ConvertTo-Json
    $response = Invoke-RestMethod -Method 'Post' -ContentType 'application/json' -Uri $uri -Body $body -Headers $headers
    return $response
}
function Get-UserGroups {
    # Get all groups that a user belongs to
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $UserEmail
    )
    $uri = "https://admin.googleapis.com/admin/directory/v1/groups?domain=harnessevents.io&userKey=$UserEmail&maxResults=50"
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
function Reset-Password {
    Send-Update -t 2 -c "Sorry- this is currently a TODO item.  Please contact workshop committee for now."
    # Reset instructor password to default
    # $uri = "https://admin.googleapis.com/admin/directory/v1/users/$($config.InstructorEmail)"
    # Send-Update -t 0 -c "reset uri: $uri"
    # $body = @{
    #     "primaryEmail"              = $userEmail

    #     "suspended"                 = $false
    #     "password"                  = "Harness!"
    #     "changePasswordAtNextLogin" = $false
    # } | ConvertTo-Json
    # $response = Invoke-RestMethod -Method 'Put' -ContentType 'application/json' -Uri $uri -Body $body -Headers $headers
    # Send-Update -t 1 -c "Reset password to default: Harness!"
    # return $response
}
function Remove-User {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $userEmail
    )
    $uri = "https://admin.googleapis.com/admin/directory/v1/users/$userEmail"
    $response = Invoke-RestMethod -Method 'Delete' -Uri $uri -Headers $headers
    return $response

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
    Get-GoogleAccessToken
    $body = @{
        "email" = $email
        "name"  = $name
    } | ConvertTo-Json
    $response = Invoke-RestMethod -Method 'Post' -ContentType 'application/json' -Uri $uri -Body $body -Headers $headers
    Send-Update -t 0 -c "Create new group returned: $response"
    $success = $false
    $counter = 0
    $uri = "https://admin.googleapis.com/admin/directory/v1/groups?domain=harnessevents.io&query=email='$newEmail'"
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
            if ($counter -gt 10) {
                Send-Update -t 2 -c "Group creation failed after 10 tries!"
                exit
            }
            Start-sleep -s 2
        }
    } until ($success)
    #Get-UserGroups
}
function Get-GroupMembers {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string] $groupEmail,
        [Parameter()]
        [switch] $splitIntoGroups # organize the results into owners/members and provided a count
    )
    # Retrieve group key - or use cached default if none provided
    if ($groupEmail) {
        $groupKey = Get-GroupKey -g $groupEmail
    }
    else {
        $groupKey = $config.GoogleEventId
    }
    $uri = "https://admin.googleapis.com/admin/directory/v1/groups/$groupKey/members"
    $response = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers
    if ($response.members) {
        if ($splitIntoGroups) {
            $groupMembers = @{
                "owners"      = $response.members | Where-Object { $_.role -eq "OWNER" }
                "members"     = $response.members | Where-Object { $_.role -eq "MEMBER" }
                "ownerCount"  = ($response.members | Where-Object { $_.role -eq "OWNER" }).count
                "memberCount" = ($response.members | Where-Object { $_.role -eq "MEMBER" }).count
            }
            return $groupMembers
        }
        else {
            return $response.members
        }
        
    }
    return $false
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
        return $response.groups.id
    }
    else {
        Send-Update -t 2 -c "NO ID found for URI: $uri"
    }
}

# Harness Functions
function Get-HarnessConfiguration {
    Add-Choice -k "HARNESSCFG" -d "Add/Switch Harness Account" -c $($config.HarnessAccount) -f "Set-HarnessConfiguration" -t
    if ($config.HarnessPAT -and $config.HarnessAccountId -and $config.HarnessAccount) {
        Set-HarnessConfiguration -p $config.HarnessPAT
    }

}
function Add-HarnessConfig {
    if (-not $config.GoogleEventName) {
        Send-Update -t 2 -c "Expected a Google Event Name for Harness config. I'm giving up and moving to Alaska."
        exit
    }
    Set-Prefs -k "HarnessOrg" -v "event_$($config.GoogleEventName.tolower())"
    $attendees = Get-GroupMembers
    # Add needed flags
    $featureFlagsStart = gcloud storage cat gs://harnesseventsdata/config/featureflagsstart.json | Convertfrom-Json
    $currentFlags = Get-FeatureFlagStatus
    $flagsNeeded = Compare-Object @($featureFlagsStart.PSObject.Properties) @($currentFlags.PSObject.Properties) -Property Name, Value | Where-Object { $_.SideIndicator -eq "<=" }
    foreach ($flag in $flagsNeeded) {
        Update-FeatureFlag -flag $flag.Name -value $flag.Value
    }
    do {
        $currentFlags = Get-FeatureFlagStatus
        $flagsNeeded = Compare-Object @($featureFlagsStart.PSObject.Properties) @($currentFlags.PSObject.Properties) -Property Name, Value | Where-Object { $_.SideIndicator -eq "<=" }
        Send-Update -t 1 -c "Waiting for $($flagsNeeded.count) flag(s)..."
        Start-Sleep -s 2
    } until (-not $flagsNeeded)
    Enable-GoogleAuth
    Add-Organization
    Add-AttendeeRole
    foreach ($attendee in $attendees) {
        if ($attendee.role -eq "OWNER") {
            # if user is an owner, they are a Harness SE- so grant account admin
            Add-HarnessAdmin -userEmail $attendee.email
        }
        else {
            # If user is not an owner, then it is an attendee email- give them a project and attendee permissions
            $cleanProject = ($attendee.email.split("@")[0] -replace '\W', '').tolower()
            Add-Project -projectName $cleanProject
            Add-HarnessUser -projectName $cleanProject -userEmail $attendee.email
        }
    }
    Add-Choice -k "HARNESSINIT" -d "Sync Projects with Attendees" -c "$((Get-Projects).count) projects" -f Add-HarnessConfig
    Set-Prefs -k "projectsCreated" -v "true"
    Get-ClassroomStatus
}
function Get-ClassroomStatus {
    $gcpStatus = Get-DelegateStatus -d gcp
    if ($gcpStatus) {
        Set-Prefs -k "GCPDelegateId" -v $gcpStatus.name
        Add-Choice -k "GCPCONFIG" -d "Delete GCP classroom" -c "READY" -f Remove-GCPProject
    }
    else {
        Add-Choice -k "GCPCONFIG" -d "Enable GCP classrom" -c "not enabled" -f New-GCPProject
    }
    Add-Choice -k "AZCONFIG" -d "Enable Azure classroom" -c "not enabled" -f New-AZResourceGroup
    Add-Choice -k "AWSCONFIG" -d "Enable AWS classroom" -c "not enabled" -f New-AWSProject
}
function Set-HarnessConfiguration {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $presetToken
    )
    if ($presetToken) {
        $response = Test-Connectivity -harnessToken $presetToken
        if ($response) {
            Send-Update -t 0 -c "Cached token worked"
            $goodToken = $presetToken
        }
    }
    while (-not $goodToken) {
        #Show list of cached tokens
        $config.HarnessList | Format-Table -Property option, HarnessAccount, HarnessAccountId
        $accountChoice = Read-Host "Select cached token or 'a' to add new token"
        if ($accountChoice.tolower() -eq "a") {
            # Offer option to add new token
            $newToken = Read-Host -prompt "Please enter a Harness *Account admin* token or <enter> to abort"
        }
        else {
            # Or use a locally cached token
            $newToken = $config.HarnessList | Where-Object { $_.option -eq $accountChoice } | select-object -expandproperty HarnessPAT
        }
        if (!$newToken) {
            write-host -ForegroundColor red "`r`nFine don't pick a valid thing, GOSH!" 
            return
        }
        $checkToken = $newToken.split(".")
        # Check token for valid format
        if ($checkToken[0] -eq "pat" -and $checkToken.length -eq 4) {
            Send-Update -t 1 -c "Valid token format. Checking connectivity..."
            $response = Test-Connectivity -harnessToken $newToken
            if ($response) {
                Save-HarnessConfig
                $goodToken = $newToken
                Set-Prefs -k "projectsCreated"
            }
            else {
                Send-Update -t 2 -c "That token looked valid, but was rejected by the API. Please retry."
            }
        }
        else {
            Send-Update -t 2 -c "Bruh, token should start with 'pat' and have 4 sections separated by periods.  Please retry."
        }
    }
    # We have a valid Harness Account- move on to initializing projects for attendees or if done, move on to classroom setup
    if ($config.projectsCreated) {
        Add-Choice -k "HARNESSINIT" -d "Sync Projects with Attendees" -c "$((Get-Projects).count) projects" -f Add-HarnessConfig
        Get-ClassroomStatus
    }
    else {
        Add-HarnessConfig
    }
}
function Save-HarnessConfig {
    Set-Prefs -k "HarnessAccount" -v $response.data.companyName
    Set-Prefs -k "HarnessAccountId" -v $checkToken[1]
    Set-Prefs -k "HarnessPAT" -v $newToken
    if ($config.HarnessList) {
        $oldHistory = $config.HarnessList | Sort-object -property option
    }
    else {
        $oldHistory = @()
    }
    $newHistory = @([pscustomobject]@{
            "option"           = 1
            "HarnessAccount"   = $config.HarnessAccount
            "HarnessAccountId" = $config.HarnessAccountId
            "HarnessPAT"       = $config.HarnessPAT 
        })
    $counter = 2
    foreach ($item in $oldHistory) {
        $newItem = $item.HarnessAccount -ne $config.HarnessAccount
        if ($counter -lt 8 -and $newItem) {
            $newHistory += @{
                "option"           = $counter
                "HarnessAccount"   = $item.HarnessAccount
                "HarnessAccountId" = $item.HarnessAccountId
                "HarnessPAT"       = $item.HarnessPAT 
            }
        }
        $counter++
    }
    Set-Prefs -k "HarnessList" -v $newHistory
}
function Test-Connectivity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $harnessToken
    )
    $harnessAccount = $harnessToken.split(".")[1]
    $TestHarnessHeaders = @{
        "x-api-key" = $harnessToken
    }
    $uri = "https://app.harness.io/ng/api/accounts/$harnessAccount"
    try {
        $response = Invoke-RestMethod -Method 'GET' -ContentType "application/json" -uri $uri -Headers $TestHarnessHeaders
    }
    catch {
        Send-Update -t 2 -c "Failed to connect to Harness API: $($_.Exception.Message)"
        return $false
    }
    Send-Update -t 0 -c "Token validation successful!"
    $script:HarnessHeaders = @{
        'x-api-key'    = $harnessToken
        'Content-Type' = 'application/json'
    }
    $script:HarnessFFHeaders = @{
        'x-api-key'    = $config.HarnessFFToken
        'Content-Type' = 'application/json'
    }
    Set-Prefs -k "HarnessAccount" -v $response.data.companyName
    Set-Prefs -k "HarnessAccountId" -v $harnessAccount
    Set-Prefs -k "HarnessPAT" -v $harnessToken
    # OMG Why do 2 API's use DIFFERENT strings to describe the SAME ENVIRONMENT *internal sobbing*
    $fixGodDamnEnv = $response.data.cluster.replace("-","")
    $correctEnv = $fixGodDamnEnv.substring(0,1).toUpper() + $fixGodDamnEnv.substring(1)
    if ($correctEnv -ne "Prod1") {
        Send-Update -t 2 "$correctEnv isn't the expected environment (Prod1)- just FYI if something doesn't work right."
    }
    Set-Prefs -k "HarnessEnv" -v $correctEnv
    return $response
}
function Add-Project {
    # Create a project and optionally add an administrator
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $projectName,
        [Parameter()]
        [string]
        $admin
    )
    $body = @{
        "project" = @{
            "orgIdentifier" = $config.HarnessOrg
            "identifier"    = $cleanProject
            "name"          = $cleanProject
        }
    } | Convertto-Json
    $uri = "https://app.harness.io/ng/api/projects?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
    try {
        Invoke-RestMethod -Method 'POST' -ContentType "application/json" -uri $uri -Headers $HarnessHeaders -body $body | out-null
    }
    catch {
        $errorResponse = $_ | Convertfrom-Json
        if ($errorResponse.code -eq "DUPLICATE_FIELD") {
            Send-Update -t 1 -c "Project $projectName already exists in org $($config.HarnessOrg)."
        }
        else {
            Send-Update -t 2 -c "Faied to create organization with error: $errorResponse"
            exit
        }   
    }
}
function Get-Projects {
    $uri = "https://app.harness.io/v1/orgs/$($config.HarnessOrg)/projects&limit=50&sort=name&order=ASC"
    $response = Invoke-RestMethod -method 'GET' -uri $uri -headers $HarnessHeaders
    return $response
}
function Get-Roleassignments {
    $uri = "https://app.harness.io/authz/api/roleassignments?pageIndex=0&pageSize=50&sortOrders=fieldName%3Dstring%26orderType%3DASC&pageToken=string&accountIdentifier=$($config.HarnessAccountId)&orgidentifer=$($config.HarnessOrg)&projectidentifier=skinnyvegetable"
    Invoke-RestMethod -Method 'GET' -uri $uri -headers $HarnessHeaders
}
function Add-HarnessUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $userEmail,
        [Parameter(Mandatory = $true)]
        [string]
        $projectName
    )
    $uri = "https://app.harness.io/ng/api/user/users?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)&projectIdentifier=$projectName"
    $body = @{
        "emails"       = @(
            $userEmail
        )
        "roleBindings" = @(
            @{
                "roleIdentifier"          = "_project_admin"
                "roleName"                = "Project Admin"
                "roleScopeLevel"          = "project"
                "resourceGroupIdentifier" = "_all_project_level_resources"
                "managedRole"             = $false
            }
        )
    } | Convertto-Json
    Invoke-RestMethod -Method 'POST' -uri $uri -body $body -headers $HarnessHeaders -ContentType "application/json" | out-null
    $uri1 = "https://app.harness.io/ng/api/user/users?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
    $body1 = @{
        "emails"       = @(
            $userEmail
        )
        "roleBindings" = @(
            @{
                "roleIdentifier"          = "attendeeRole"
                "roleName"                = "attendeeRole"
                "roleScopeLevel"          = "organization"
                "resourceGroupIdentifier" = "_all_organization_level_resources"
                "resourceGroupName"       = "All Organization Level Resources"
                "managedRole"             = $false 
            }
        )
    } | Convertto-Json
    Invoke-RestMethod -Method 'POST' -uri $uri1 -body $body1 -headers $HarnessHeaders -ContentType "application/json" | out-null
    Send-Update -t 1 -c "Added $userEmail to $projectName project admin and $($config.HarnessOrg) attendeeRole."
}
function Add-HarnessAdmin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $userEmail
    )
    $uri = "https://app.harness.io/ng/api/user/users?accountIdentifier=$($config.HarnessAccountId)"
    $body = @{
        "emails"       = @(
            $userEmail
        )
        "roleBindings" = @(
            @{
                "roleIdentifier"          = "_account_admin"
                "roleName"                = "Account Admin"
                "roleScopeLevel"          = "account"
                "resourceGroupIdentifier" = "_all_resources_including_child_scopes"
                "managedRole"             = $false
            }
        )
    } | Convertto-Json
    Invoke-RestMethod -Method 'POST' -uri $uri -body $body -headers $HarnessHeaders -ContentType "application/json" | out-null
    Send-Update -t 1 -c "Added $userEmail to account admin role."
}
function Add-AttendeeRole {
    $uri = "https://app.harness.io/v1/orgs/$($config.HarnessOrg)/roles"
    $body = @{
        "identifier"  = "attendeeRole"
        "name"        = "attendeeRole"
        "permissions" = @(
            "idp_scorecard_view"
            "idp_scorecard_edit"
            "idp_scorecard_delete"
            "idp_layout_view"
            "idp_layout_edit"
            "idp_integration_view"
            "idp_integration_create"
            "idp_integration_edit"
            "idp_integration_delete"
            "core_environment_view"
            "core_environment_access"
            "core_environmentgroup_view"
            "core_environmentgroup_access"
            "core_governancePolicy_view"
            "core_governancePolicySets_evaluate"
            "core_governancePolicy_edit"
            "core_governancePolicySets_edit"
            "core_service_view"
            "core_service_access"
            "core_template_view"
            "core_template_access"
            "core_secret_view"
            "core_secret_access"
            "core_connector_view"
            "core_connector_access"
            "core_file_view"
            "core_file_access"
            "core_dashboards_view"
            "core_delegate_view"
            "core_delegateconfiguration_view"
        )
    } | Convertto-Json
    try {
        Invoke-RestMethod -Method 'POST' -ContentType "application/json" -uri $uri -Headers $HarnessHeaders -body $body | out-null
    }
    catch {
        $errorResponse = $_ | Convertfrom-Json
        if ($errorResponse.code -eq "DUPLICATE_FIELD") {
            Send-Update -t 1 -c "AttendeeRole already exists."
        }
        else {
            Send-Update -t 2 -c "Faied to create organization with error: $errorResponse"
            exit
        }
    }
}
function Add-ProjectAdmin {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $projectName,
        [Parameter(Mandatory = $true)]
        [string]
        $user
    )
    $uri = "https://app.harness.io/authz/api/roleassignments?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)&projectIdentifier=$projectName"
    $body = @{
        "project" = @{
            "resourceGroupIdentifier" = "_all_project_level_resources"
            "roleIdentifier"          = "_project_admin"
            "principal"               = @{
                "scopeLevel" = "project"
                "identifier" = $user
                "type"       = "user"
            }
        }
    } | Convertto-Json
    try {
        Invoke-RestMethod -Method 'POST' -ContentType "application/json" -uri $uri -Headers $HarnessHeaders -body $body
    }
    catch {
        $errorResponse = $_ | Convertfrom-Json
        Send-Update -t 2 -c "Faied to add admin $user to project $projectName with error: $errorResponse"
        exit
    }
}
function Add-Organization {
    $harnessOrg = $config.HarnessOrg
    $body = @{
        "organization" = @{
            "identifier" = $harnessOrg
            "name"       = $harnessOrg
        }
    } | Convertto-Json
    $uri = "https://app.harness.io/ng/api/organizations?accountIdentifier=$($config.HarnessAccountId)"
    try {
        Invoke-RestMethod -Method 'POST' -ContentType "application/json" -uri $uri -Headers $HarnessHeaders -body $body | Out-Null
    }
    catch {
        $errorResponse = $_ | Convertfrom-Json
        if ($errorResponse.code -eq "DUPLICATE_FIELD") {
            Send-Update -t 1 -c "Organization $harnessOrg already exists."
        }
        else {
            Send-Update -t 2 -c "Faied to create organization with error: $errorResponse"
            exit
        }
    }
}
function Get-Organizations {
    # if successful, returns org detail: identifier, name, description, tags
    # if failure, returns $false
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $orgName
    )
    $uri = "https://app.harness.io/ng/api/organizations?accountIdentifier=$($config.HarnessAccountId)&searchTerm=$orgName"
    $response = Invoke-RestMethod -Method 'GET' -uri $uri -Headers $HarnessHeaders
    if ($response.data.content.organization) {
        return $response.data.content.organization
    }
    return $false
}
function Enable-GoogleAuth {
    $uri1 = "https://app.harness.io/ng/api/authentication-settings/oauth/update-providers?accountIdentifier=$($config.HarnessAccountId)"


    $body = @{
        "allowedProviders" = @(
            "GOOGLE"
        )
        "settingsType"     = "OAUTH"

    } | Convertto-Json
    Invoke-RestMethod -method 'PUT' -ContentType "application/json" -Uri $uri1 -Headers $HarnessHeaders -Body $body | out-null
    $uri2 = "https://app.harness.io/ng/api/authentication-settings/update-auth-mechanism?accountIdentifier=$($config.HarnessAccountId)&authenticationMechanism=OAUTH"
    Invoke-RestMethod -method 'PUT' -Uri $uri2 -Headers $HarnessHeaders | out-null
}
function Add-OrgSecret {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $SecretName,
        [Parameter(Mandatory = $true)]
        [string]
        $content, # text or specify location of file and use $file switch
        [Parameter()]
        [switch]
        $file
    )
    #$secrets = gcloud secrets list --filter="labels.org:*" --format=json | Convertfrom-Json
    if ($file) {
        # confirm file exists
        if (-not (Test-Path $content)) {
            Send-Update -t 2 -c "Cannot upload secret. File not found: $file"
            return $false
        }
        # Add file (google key json, etc)
        $uri = "https://app.harness.io/ng/api/v2/secrets/files?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
        $form = @{
            "spec" = "String"
        } | Convertto-Json
        #         #File names
        #         $PathToFile = $content


        #         #Byte stream and encoding
        #         $PackageByteStream = [System.IO.File]::ReadAllBytes("$PathToFile")
        #         $Encoding = [System.Text.Encoding]::GetEncoding("ISO-8859-1")
        #         $FileEncoding = $Encoding.GetString($PackageByteStream)

        #         #Create the content body
        #         $Boundary = (New-Guid).ToString()
        #         $ContentBody = "--$Boundary
        # Content-Disposition: form-data; spec=""Json""; name=""yourmom""; uploadedInputStream=""$FileEncoding""
        # Content-Type: application/octet-stream


        # --$Boundary--
        # "

        #         #Parameter Object
        #         $Parameters = @{
        #             Uri         = "https://app.harness.io/ng/api/v2/secrets/files?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
        #             Method      = "Post"
        #             ContentType = "multipart/form-data; boundary=`"$Boundary`""
        #             Headers     = $HarnessHeaders
        #             Body        = $ContentBody
        #         }


        #         Invoke-RestMethod @Parameters
        $fileBin = [System.IO.File]::ReadAllBytes("$PSScriptRoot\$filePath")
        $data = @{
            "spec" = "String"
            "file" = $fileBin
        }
        $temp = Invoke-RestMethod -Uri $uri -Method POST -Body $data -ContentType 'multipart/form-data'

        Write-Output $temp
        $response = Invoke-RestMethod -Method 'POST' -Uri $uri -Form $form -Headers $HarnessHeaders -ContentType "multipart/form-data; charset=iso-8859-1;"
    }
    else {
        #Add text
        $uri = "https://app.harness.io/ng/api/v2/secrets?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
        $body = @{
            "secret" = @{
                "type"          = "SecretText"
                "name"          = $SecretName
                "identifier"    = $SecretName
                "orgIdentifier" = $config.HarnessOrg
                "spec"          = @{
                    "type"                    = "SecretTextSpec1"
                    "secretManagerIdentifier" = "org.harnessSecretManager"
                    "valueType"               = "Inline"
                    "value"                   = $content
                } 
            } 
        } | Convertto-Json
        $uri
        $body
        $response = Invoke-RestMethod -Method 'POST' -ContentType "application/json" -uri $uri -Headers $HarnessHeaders -body $body
    }
    if ($response.data) {
        return $response.data
    }
    return $false
}
function Get-DelegateConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $delegatePrefix #expecting gcp/az/aws
    )
    $uri = "https://app.harness.io/ng/api/download-delegates/kubernetes?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
    $body = @{
        "name" = "$delegatePrefix-$($config.GoogleEventName)-delegate"
    } | ConvertTo-Json
    $response = Invoke-RestMethod -Method 'POST' -ContentType 'application/json' -uri $uri -Headers $HarnessHeaders -body $body
    $response | Out-File -FilePath "$delegatePrefix.yaml" -Force
    Send-Update -t 1 -c "Downloaded gcp delegate to $delegatePrefix.yaml"
}
function Get-DelegateStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $delegatePrefix #expecting gcp/az/aws
    )
    $uri = "https://app.harness.io/ng/api/delegate-setup/listDelegates?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
    $body = @{
        "status"       = "CONNECTED"
        "filterType"   = "Delegate"
        "delegateName" = "$delegatePrefix-$($config.GoogleEventName)-delegate"
    } | Convertto-Json
    $response = Invoke-RestMethod -method 'POST' -uri $uri -headers $HarnessHeaders -body $body -ContentType 'application/json'
    if ($response.resource) {
        return $response.resource
    } 
    return $false
}
function Add-Delegate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $delegatePrefix #expecting gcp/az/aws
    )
    Send-Update -t 1 -c "Get $delegatePrefix Delegate Config" -r "Get-DelegateConfig -d $delegatePrefix"
    Send-Update -t 1 -c "Apply $delegatePrefix delegate yaml" -r "kubectl apply -f $delegatePrefix.yaml"
    $uri = "https://app.harness.io/ng/api/delegate-setup/listDelegates?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
    $body = @{
        "status"     = "CONNECTED"
        "filterType" = "Delegate"
    } | Convertto-Json
    $counter = 0
    While (-not $DelegateAvailable) {
        Send-Update -t 1 -c "Waiting for delegate to be available..."
        $DelegateAvailable = Invoke-RestMethod -method 'POST' -uri $uri -headers $HarnessHeaders -body $body -ContentType "application/json"
        $counter++
        if ($counter -ge 10) {
            Send-Update -t 2 -c "Sorry... delegate did not load correctly."
            exit
        }
        Start-sleep -s 3
    }
    Send-Update -t 1 -c "$DelegatePrefix Delegate is connected and ready!"
    Get-ClassroomStatus
}
function Remove-Delegate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $delegatePrefix #expecting gcp/az/aws
    )
    $delegatePrefix = $delegatePrefix.toupper()
    $delegateId = $config.($delegatePrefix + "DelegateId")
    $uri = "https://app.harness.io/ng/api/delegate-setup/delegate/$($delegateId)?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
    $DelegateAvailable = Invoke-RestMethod -method 'DELETE' -uri $uri -headers $HarnessHeaders -ContentType "application/json"
    return $DelegateAvailable

}
function Get-FeatureFlagStatus {
    $uri = "https://harness0.harness.io/cf/admin/features?accountIdentifier=l7B_kbSEQD2wjrM7PShm5w&projectIdentifier=FFOperations&orgIdentifier=PROD&environmentIdentifier=$($config.HarnessEnv)&targetIdentifierFilter=$($config.HarnessAccountId)&pageSize=10000"
    $response = Invoke-RestMethod -Uri $uri -method 'GET' -Headers $HarnessFFHeaders
    # parse this ridiculous API output for the values relevant to this account
    $currentFlags = [pscustomobject]@{}
    foreach ($item in $response.features) {
        $value = $item.envProperties.variationMap | Where-Object { $_.targets.identifier -eq $($config.HarnessAccountId) } | select-object -expandproperty variation
        #write-host "$($item.identifier):$value"
        $currentFlags | Add-Member -MemberType NoteProperty -name $item.identifier -value $value -Force
    }
    return $currentFlags
}
function Update-FeatureFlag {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $flag,
        [Parameter(Mandatory = $true)]
        [string]
        $value
    )
    $body = @{
        "instructions" = @(
            @{
                "kind"       = "addTargetToFlagsVariationTargetMap"
                "parameters" = @{
                    "features" = @(
                        @{
                            "identifier" = $flag
                            "variation"  = $value
                        }
                    )
                }
            }
        )
    } | ConvertTo-Json -Depth 10
    $uri = "https://harness0.harness.io/cf/admin/targets/$($config.HarnessAccountId)?accountIdentifier=l7B_kbSEQD2wjrM7PShm5w&orgIdentifier=PROD&projectIdentifier=FFOperations&environmentIdentifier=$($config.HarnessEnv)"
    $response = Invoke-RestMethod -Method 'Patch' -ContentType "application/json" -uri $uri -Headers $HarnessFFHeaders -body $body
    Send-Update -t 1 -c "feature flag $flag variation set: $value"
    return $response
}

# Google Project Functions
function New-GCPProject {
    # Use Harness Org as the project name- adjusting for the different character requirements *insert massive eyeroll here*
    Set-Prefs -k "GoogleProject" -v $config.HarnessOrg.replace("_","-")
    # Get organization of admin project to assign to new project
    $googleAdminAncestors = Send-Update -t 1 -c "Retrieve org info" -r "gcloud projects get-ancestors $($config.AdminProjectId) --format=json" | ConvertFrom-Json
    Set-Prefs -k "GoogleOrgId" -v ($googleAdminAncestors | Where-Object { $_.type -eq "organization" }).id
    # Get billing project of admin project to associate with this project
    $AdminProjectInfo = Send-Update -t 1 -c "Retrieving billing account" -r "gcloud billing accounts list --filter=displayName='HarnessEvents' --format=json" | ConvertFrom-Json
    Set-Prefs -k "GoogleBillingProject" -v $AdminProjectInfo.name.split("/")[1]
    # Use Harness Org as the project name- adjusting for the different character requirements *insert massive eyeroll here*
    Set-Prefs -k "GoogleProject" -v $config.HarnessOrg.replace("_","-")
    # Create new google project if needed
    $projectCheck = Send-Update -t 1 -c "Check for existing project" -r "gcloud projects list --filter='name:$($config.GoogleProject)' --format=json" | convertfrom-json
    if ($projectCheck) {
        # Project already exists- skip creation
        Send-Update -t 1 -c "Project already exists- skipping creation."
    }
    else {
        # Generate a unique project ID following all of Google's goofy rules
        if ($config.GoogleProject.length -gt 16) {
            Set-Prefs -k "GoogleProject" -v $config.GoogleProject.substring(0,16)
        }
        $projectID = "$($config.GoogleProject)-$(Get-Randomstring)"
        $projectID = $projectID.tolower()
        Send-Update -t 1 -c "Create $($config.GoogleProject) project" -r "gcloud projects create $projectID --name=""$($config.GoogleProject)"" --organization=$($config.GoogleOrgId) --set-as-default -q"
    }
    while (-not $projectDetails) {
        $projectDetails = Send-Update -t 1 -c "Waiting for project to be available..." -r "gcloud projects list --filter='name:$($config.GoogleProject)' --format=json" | Convertfrom-Json   
        Start-Sleep -s 6
    }
    Set-Prefs -k "GoogleProjectId" -v $projectDetails.projectId
    # Associate project with billing account
    Send-Update -t 1 -c "Associate billing account" -r "gcloud billing projects link $($config.GoogleProjectId) --billing-account=$($config.GoogleBillingProject)"
    # Add users to project
    Send-Update -t 1 -c "Add group 300@harnessevents.io to project" -r "gcloud projects add-iam-policy-binding $($config.GoogleProjectId) --member='group:300@harnessevents.io' --role='roles/owner' -q" | out-null
    Send-Update -t 1 -c "Add group $($config.GoogleEventEmail) to project" -r "gcloud projects add-iam-policy-binding $($config.GoogleProjectId) --member='group:$($config.GoogleEventEmail)' --role='roles/editor' -q" | out-null
    # Create worker, get keys, add to IAM
    Send-Update -t 1 -c "Create service account" -r "gcloud iam service-accounts create worker1"
    Send-Update -t 1 -c "Grant service account permissions" -r "gcloud iam service-accounts add-iam-policy-binding worker1@$($config.GoogleProjectId).iam.gserviceaccount.com --member=serviceAccount:worker1@$($config.GoogleProjectId).iam.gserviceaccount.com --role='roles/editor'"
    Send-Update -t 1 -c "Generate local key json file" -r "gcloud iam service-accounts keys create worker1.json --iam-account=worker1@$($config.GoogleProjectId).iam.gserviceaccount.com"
    # Enable API's needed for workshops
    Send-Update -t 1 -c "Enabling compute API" -r "gcloud services enable compute.googleapis.com"
    Send-Update -t 1 -c "Enabling kubernetes API" -r "gcloud services enable container.googleapis.com"
    New-GCPcluster
}
function New-GCPcluster {
    Send-Update -t 1 -c "Create kubernetes cluster" -r "gcloud container clusters create harnessevent -m e2-standard-4 --num-nodes=1 --zone=us-west4 --no-enable-insecure-kubelet-readonly-port"
    Send-Update -t 1 -c "Retrieve kubernetes credentials" -r "gcloud container clusters get-credentials harnessevent --zone=us-west4"
    Add-Delegate -d gcp
}
function Remove-GCPProject {
    Send-Update -t 2 -c "Need remove gcp project logic"

    Get-ClassroomStatus
}

##TODO Azure Resource Group Functions
function New-AZResourceGroup {
    Send-Update -t 1 -c "Sorry, this is not built yet!"
}

##TODO AWS Project Functions
function New-AWSProject {
    Send-Update -t 1 -c "Sorry, this is not built yet!"
}

#Main
Test-PreFlight
Get-Prefs($Myinvocation.MyCommand.Source)
Get-GoogleLogin
while ($choices.count -gt 0) {
    $cmd = Get-Choice($choices)
    if ($cmd) {
        Invoke-Expression $cmd.callFunction
    }
    else { write-host -ForegroundColor red "`r`nY U no pick existing option?" }
}
#Add-OrgSecret -s GCPplatform -c worker1.json -f