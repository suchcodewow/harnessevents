# VSCODE: ctrl/cmd+k+1 folds all functions, ctrl/cmd+k+j unfold all functions. Check '.vscode/launch.json' for any current parameters
param (
    [switch] $help, # show other command options and exit
    [switch] $verbose, # default output level is 1 (info/errors), use -v for level 0 (debug/info/errors)
    [switch] $cloudCommands, # enable to show commands
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
    if ($run) {
        $Params['ForegroundColor'] = "Magenta"; $start = "[$whatIfComment>]"
    }
    else {
        Switch ($type) {
            0 { $Params['ForegroundColor'] = "DarkBlue"; $start = "[.]" }
            1 { $Params['ForegroundColor'] = "DarkGreen"; $start = "[-]" }
            2 { $Params['ForegroundColor'] = "DarkRed"; $start = "[X]" }
            default { $Params['ForegroundColor'] = "Gray"; $start = "" }
        }
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
    if ($cloudCommands) { $script:showCommands = $true } else { $script:showCommands = $false }
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
        $script:eventList = @("option","Name","ID", "default")
    }
    else {
        $script:choiceColumns = @("Option", "description", "current")
        $script:providerColumns = @("option", "provider", "name")
        $script:eventList = @("option","Name")
    }
    # Load preferences/settings.  Access with $config variable anywhere.  Set-Prefs automatically updates $config variable and saves to file
    # Set with Set-Prefs function
    if ($scriptPath) {
        $script:configFile = "$scriptPath.conf"
        if (Test-Path $configFile) {
            Send-Update -c "Reading config" -t 0
            $script:config = Get-Content $configFile -Raw | ConvertFrom-Json -AsHashtable
        }
        else {
            $script:config = @{}
            $config["schemaVersion"] = "2.0"
            if ($MyInvocation.MyCommand.Name) {
                $config | ConvertTo-Json | Out-File $configFile
                Send-Update -c "CREATED config" -t 0
            }
        }
    }
    Set-Prefs -k userCount -v $users
}
function Set-Prefs {
    param(
        $u, # Add this value to a user's settings (mostly for mult-user setup sweetness)
        $k, # key
        $v # value
    )
    # Create Users hashtable if needed
    if (-not $config.Users) { $config.Users = @{} }
    if ($u) {
        # Focus on user subkey
        if ($k) {
            # Create User nested hashtable if needed
            if (-not $config.Users.$u) { $config.Users.$u = @{} }
            if ($v) {
                # Update User Value
                Send-Update -c "Updating $u user key: $k -> $v" -t 0
                $config.Users.$u[$k] = $v 
            }
            else {
                if ($k -and $config.Users.$u.containsKey($k)) {
                    # Attempt to delete the user's key
                    Send-Update -c "Deleting $u user key: $k" -t 0
                    $config.Users.$u.remove($k)
                }
                else {
                    Send-Update -c "$u Key didn't exist: $k" -t 0
                }
            }
        }
        else {
            if ($config.Users.$u) {
                # Attempt to remove the entire user
                Send-Update -c "Removing $u user" -t 0
                $config.Users.remove($u)
            }
            else {
                Send-Update -c "User $u didn't exists" -t 0
            }
        }
    }
    else {
        # Update at main schema level
        if ($v) {
            Send-Update -c "Updating key: $k -> $v" -t 0
            $config[$k] = $v 
        }
        else {
            if ($k -and $config.containsKey($k)
            ) {
                Send-Update -c "Deleting config key: $k" -t 0
                $config.remove($k)
            }
            else {
                Send-Update -c "Key didn't exist: $k" -t 0
            }
        }     
    }
    if ($MyInvocation.MyCommand.Name) {
        $config | ConvertTo-Json | Out-File $configFile
    }
    else {
        Send-Update -c "No command name, skipping write" -t 0
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
    #example: Add-Choice -k 'key' -d 'description' -c 'current' -f 'function' -p 'parameters'
    param(
        [string] $key, # key identifying this choice, unique only
        [string] $description, # description of item
        [string] $current, # current selection of item, if applicable
        [string] $function, # function name to call if changing item
        [object] $parameters # parameters needed in the function
    )
    # If this key exists, delete it and anything that followed
    Send-Update -c "Add choice: $key" -t 0
    $keyOption = $choices | Where-Object { $_.key -eq $key } | select-object -expandProperty Option -first 1
    if ($keyOption) {
        $staleOptions = $choices | Where-Object { $_.Option -ge $keyOption }
        $staleOptions | foreach-object { Send-Update -c "Removing $($_.Option) $($_.key)" -t 0; $choices.remove($_) }
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

# Event Functions
function Add-Event {
    param(
        [string] $e, # event
        [string] $n, # name of item
        [string] $i, # item unique identifier
        [switch] $d # [$true/$false] default option
    )
    #---Add an option selector to item then add to provider list
    $eventItem = New-Object PSCustomObject -Property @{
        Name    = $n
        ID      = $i
        default = $d
        option  = $providerLIst.count + 1
    }
    [void]$eventList.add($eventItem)
    Send-Update -t 0 -c "Added: $n with id: $i"
}
function Get-Events {
    # Check token status/refresh
    Get-GoogleAccessToken
    # Create/Clear event list
    $eventList.Clear()
    # Get groups for current user
    $currentGroups = Get-UserGroups -u $($config.GoogleUser)
    foreach ($group in $currentGroups) {
        # Filter to event groups only
        if ($group.name.length -ge 5) {
            if ($group.name.substring(0,5) -eq "event-") {
                if ($group.id -eq $config.currentGroupId) { $Params['d'] = $true }
                Add-Event @Params -n $group.name -i $group.id
            }
        }
        # Provide option to create a new event
        Add-Event -n "Create new Event"-i "_create"
    }
}
function Set-Event {
    param(
        [object] $preset # optional preset to bypass selection
    )
    $providerSelected = $preset
    while (-not $providerSelected) {
        write-output $providerList | sort-object -property Option | format-table $providerColumns | Out-Host
        $newProvider = read-host -prompt "Which environment to use? <enter> to cancel"
        if (-not($newProvider)) {
            return
        }
        $providerSelected = $providerList | Where-Object { $_.Option -eq $newProvider } | Select-Object -first 1
        if (-not $providerSelected) {
            write-host -ForegroundColor red "`r`nY U no pick valid option?" 
        }
    }
    $functionProperties = @{provider = $providerSelected.Provider; id = $providerSelected.identifier.tolower(); userid = $providerSelected.userid.tolower() }

    # Reset choices
    # Add option to change destination again
    Add-Choice -k "TARGET" -d "Switch Cloud Provider" -c "$($providerSelected.Provider) $($providerSelected.Name)" -f "Set-Provider" -p $functionProperties
    # build options for specified provider
    switch ($providerSelected.Provider) {
        "Azure" {
            # Set the Azure subscription
            Send-Update -t 1 -c "Azure: Set Subscription" -r "az account set --subscription $($providerSelected.identifier)"
            Set-Prefs -k "provider" -v "azure"
            Add-AzureSteps 
        }
        "AWS" {
            Send-Update -t 1 -c "AWS: Set region"
            Set-Prefs -k "provider" -v "aws"
            Add-AWSSteps 
        }
        "GCP" { 
            # set the GCP Project
            Send-Update -OutputSuppression -t 1 -c "GCP: Set Project" -r "gcloud config set account '$($providerSelected.identifier)' --no-user-output-enabled"
            Set-Prefs -k "provider" -v "gcp"
            Add-GCPSteps 
        }
    }
}

# Google Admin Functions
function Get-GoogleAccessToken {
    # Check for valid token
    if ($config.GoogleAccessToken -and $config.GoogleAccessTokenTimestamp) {
        $TimeDiff = $(Get-Date) - $config.GoogleAccessTokenTimestamp
        if ($TimeDiff.TotalMinutes -lt 40) {
            Send-Update -t 1 -c "Google Workspace Token age is OK: $([math]::round($TimeDiff.TotalMinutes))m."
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
    $url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=$clientId&redirect_uri=http://localhost:$port&response_type=code&scope=$Scope"
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
    $webPageResponse = "<html><head><script>window.close();</script></head><body><div>Safe to close window </div></body></html>"
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
        Send-Update -t 1 -c "Successfully retrieved a new token and timestamp."
    }
    else {
        Send-Update -t 2 -c "Unexpected error while retrieving access token."
    }
}
function New-User {
    [CmdletBinding()]
    param (
        [string] $user,
        [string] $group
    )
    $headers = @{
        "Authorization" = "Bearer $($config.GoogleAccessToken)"
        #"ContentType"   = "appplication/json"
    }
    $body = @{
        "primaryEmail"              = "bill.hope@harnessevents.io"
        # "emails"                    = @(
        #     @{
        #         "address" = "pleasework@harnessevents.io"
        #         "type"    = "work"
        #         "primary" = $true
        #     }
        # )
        "name"                      = @{
            "givenName"  = "tom"
            "familyName" = "yahboi"
        }
        "suspended"                 = false
        "password"                  = "Harness!"
        "changePasswordAtNextLogin" = false
    } | ConvertTo-Json
    $response = Invoke-RestMethod -Method 'Post' -ContentType 'application/json' -Uri 'https://admin.googleapis.com/admin/directory/v1/users' -Body $body -Headers $headers
    return $response
}
function New-Group {
    $headers = @{
        "Authorization" = "Bearer $($config.GoogleAccessToken)"
    }
    $body = @{
        "email" = "eventmail@harnessevents.io"
        "name"  = "event"
    } | ConvertTo-Json
    $body
    $response = Invoke-RestMethod -Method 'Post' -ContentType 'application/json' -Uri $uri -Body $body -Headers $headers
    return $response
}
function Add-UserToGroup {
    param (
        [Parameter(Mandatory = $true)]
        [string] $user,
        [Parameter(Mandatory = $true)]
        [string] $group,
        [switch] $owner
    )
    # Retrieve group key
    $groupKey = Get-GroupKey -g $group
    # Build api call for group
    $uri = "https://admin.googleapis.com/admin/directory/v1/groups/$groupKey/members"
    Send-Update -t 1 -c "Group URI: $uri"
    $headers = @{
        "Authorization" = "Bearer $($config.GoogleAccessToken)"
    }
    if ($owner) { $role = "OWNER" } else { $role = "MEMBER" }
    $body = @{
        "email" = $user
        "role"  = $role
    } | ConvertTo-Json
    $response = Invoke-RestMethod -Method 'Post' -ContentType 'application/json' -Uri $uri -Body $body -Headers $headers
    return $response
}
function Get-GroupKey {
    param (
        [string] $GroupName
    )
    $headers = @{
        "Authorization" = "Bearer $($config.GoogleAccessToken)"
    }
    $uri = "https://admin.googleapis.com/admin/directory/v1/groups?domain=harnessevents.io&query=name='$GroupName'"
    $response = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers
    if ($response.groups.id) {
        return $response.groups.id
    }
    else {
        Send-Update -t 2 -c "NO ID found for URI: $uri"
    }
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
function Get-UserGroups {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $UserEmail
    )
    $headers = @{
        "Authorization" = "Bearer $($config.GoogleAccessToken)"
    }
    $uri = "https://admin.googleapis.com/admin/directory/v1/groups?userKey=$UserEmail&maxResults=50"
    Send-Update -t 0 -c "Getting Usergroups for uri: $uri"
    $response = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers
    return $response.groups
}

# Gameplay Loop
# function Get-Event {
#     while (-not $eventSelected) {

#         write-output $eventList | sort-object -property Option | format-table $providerColumns | Out-Host
#         $newProvider = read-host -prompt "Which event to use? to cancel"
#         if (-not($newProvider)) {
#             return
#         }
#         $eventSelected = $eventList | Where-Object { $_.Option -eq $newProvider } | Select-Object -first 1
#         if (-not $providerSelected) {
#             write-host -ForegroundColor red "`r`nY U no pick valid option?" 
#         }
#     }
# }

#Main
Get-Prefs($Myinvocation.MyCommand.Source)
#$groups = Get-Events
#New-User
#New-Group
#Add-UserToGroup -u bill.hope@harnessevents.io -g event
Get-Events