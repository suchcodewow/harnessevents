# VSCODE: ctrl/cmd+k+1 folds all functions, ctrl/cmd+k+j unfold all functions. Check '.vscode/launch.json' for any current parameters
# VSCODE: use setting ["powershell.codeFolding.showLastLine": false] to hide the trailing } of each function
param (
    [switch] $aws,                          # enable aws classroom (optional for headless mode)
    [switch] $azure,                        # enable azure classroom (optional for headless mode)
    [switch] $cloudCommands,                # enable to show commands
    [switch] $gcp,                          # enable gcp classroom (optional for headless mode)
    [string] $googleCloudProjectOverride,   # override project creation to use a specific project
    [switch] $headless,                     # deploy automatically. all [HEADLESS MODE] parameters become mandatory
    [int] $hourLimit,                    # [JANITOR MODE] max event lifespan in hours
    [string] $eventName,                    # [HEADLESS MODE] specifiy event name
    [string] $instructorName,               # [HEADLESS MODE] specify instructorName
    [switch] $help,                         # show other command options and exit
    [switch] $janitorMode,                  # sweep sweep! all [JANITOR MODE] parameterse become required
    [switch] $logReset,                     # enable to reset log between runs
    [switch] $removeauto,                   # remove all elements based on current conf file
    [switch] $verbose,                      # level 0 (debug/info/errors) output (versus standard level 1 info/errors)
    [int] $userCount                        # [HEADLESS MODE] specify number of attendees (default is 3)
)

# Core Functions
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
    # Send-Update -c "Add choice: $key" -t 0
    # If this key exists, delete it and anything that followed
    $keyOption = $choices | Where-Object { $_.key -eq $key } | select-object -expandProperty Option -first 1
    if ($keyOption) {
        $staleOptions = $choices | Where-Object { $_.Option -ge $keyOption }
        $staleOptions | foreach-object {
            #Send-Update -c "Removing $($_.Option) $($_.key)" -t 0
            $choices.remove($_)
        }
    }
    # Add todo flag if switch used
    $todoIndicator = "<---recommended----"
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
function Get-Choice() {
    # Present list of options and get selection
    write-output $choices | sort-object -property Option | format-table $choiceColumns | Out-Host
    $recommended = $choices | where-Object { $_.current -eq "<---recommended----" }
    if ($recommended) {
        $recommendText = "(Recommended: #$($recommended.Option)) "
    }
    $cmd_selected = read-host -prompt "Which option? $recommendText[<enter> to quit]"
    if (-not($cmd_selected)) {

        write-host "buh bye!`r`n" | Out-Host
        exit
    }
    if ($cmd_selected -eq 0) { Get-Quote }
    $cmd = $choices | Where-Object { $_.Option -eq $cmd_selected } | Select-Object -first 1
    if ($cmd) {
        Invoke-Expression $cmd.callFunction
    }
    else { write-host -ForegroundColor red "`r`nY U no pick existing option?" }
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
    if ($help) { Get-Help }
    if ($verbose) { $script:outputLevel = 0 } else { $script:outputLevel = 1 }
    if ($cloudCommands) { $script:showCommands = $true } else { $script:showCommands = $false }
    if ($logReset) { $script:retainLog = $false } else { $script:retainLog = $true }
    if ($aws) { $script:useAWS = $true }
    if ($azure -eq $true) { $script:useAzure = $true }
    if ($gcp) { $script:useGCP = $true }
    if ($multiUserMode) { $script:multiUserMode = $true }
    if ($googleCloudProjectOverride) { $script:googleCloudProjectOverride }
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

#Automated Functions
function Get-HeadlessMode {
    # Run a headless automate deploy if cmd line switch used
    # The process expects `gcloud auth activate-service-account` was already run with clousdk service account
    if (-not $headless) {
        return
    }
    Set-Prefs -k "headless" -v $true
    Send-Update -t 1 -c "Running Headless Deployment"
    # Error out with any problems
    $ErrorActionPreference = "Stop"
    # Use cli provided instructor name if present
    if ($instructorName) {
        $currentUser = $instructorName
    }
    else { 
        # this will use the cloudsdk account- typically used for daily testing
        $currentUser = gcloud auth list --format='value(account)'
    }
    Set-Prefs -k "GoogleUser" -v $currentUser
    Set-Prefs -k "InstructorEmail" -v "$($currentUser.split("@")[0])@harnessevents.io"
    if ($gcp) { Set-Prefs -k "UseGoogleClassroom" -v "ENABLED" }
    else { Set-Prefs -k "UseGoogleClassroom" }
    if ($aws) { Set-Prefs -k "UseAwsClassroom" -v "ENABLED" }
    else { Set-Prefs -k "UseAwsClassroom" }
    if ($azure) { Set-Prefs -k "UseAzureClassroom" -v "ENABLED" }
    else { Set-PRefs --k "UseAzureClassroom" }
    if ($userCount) { Set-Prefs -k "UserEventCount" -v $userCount }
    else { Set-Prefs -k "UserEventCount" -v 3 }
    if ($eventName) { Set-Prefs -k "EventName" -v $eventName }
    else { Set-Prefs -k "EventName" -v $(Get-UserName) }
    # Currently the only required item is some kind of username
    if (-not $currentUser) {
        Send-Update -t 2 -c "No instructor email provided.  Is it illegal in 23 US states to continue without one.  Nice try though."
        exit
    }
    New-Event
    Test-Connectivity -harnessToken $config.HarnessEventsPAT | Out-Null
    Sync-Event
    Send-Update -t 1 -c "End Headless Mode"
    exit
}
function Get-JanitorMode {
    if (-not $janitormode) {
        return
    }
    if ($hourLimit) {
        $maxEventHours = $hourLimit
    }
    else {
        Send-Update -t 2 -c "The -hourLimit <hours> flag must be set, you silly billy."
        exit
    }
    Send-Update -t 1 -c "Running event cleanup"
    $validEvents = @()
    $expiredOrgs = @()
    $validGCPProjects = @()
    $validAWSProjects = @()
    $validAzureProjects = @()
    Get-GoogleAccessToken
    # load all open events
    $openEvents = gcloud storage ls gs://harnesseventsdata/events/open/*.json --verbosity=none
    foreach ($eventJson in $openEvents) {
        $e = gcloud storage cat $eventJson | ConvertFrom-Json
        $TimeDiff = $(Get-Date) - $e.GoogleAppTokenTimestamp
        # if event is expired, mark it for removal
        if ($TimeDiff.TotalHours -gt $maxEventHours) {
            Send-Update -t 1 -c "Event $($e.GoogleEventName) is $($TimeDiff.Totalhours)h old exceeding limit of $($maxEventHours)h."
            if ($e.HarnessAccount -and $e.HarnessOrg -and $e.HarnessAccountId -and $e.HarnessPat) {
                $expiredOrgs += [PSCustomObject]@{
                    account    = $e.HarnessAccount
                    org        = $e.HarnessOrg
                    id         = $e.HarnessAccountId
                    pat        = $e.HarnessPat
                    HarnessEnv = $e.HarnessEnv
                }
                Send-Update -t 1 -c "Added $($e.HarnessOrg) in $($e.HarnessAcount) to expired events."
            }
            else {
                Send-Update -t 2 -c "Gross! One of these was missing- account: $($e.HarnessAccount) org: $($e.HarnessOrg) id: ($e.HarnessAccountId) pat: $($e.HarnessPat)"
            }
            gcloud storage mv $eventJson gs://harnesseventsdata/events/closed/$(Split-Path $eventJson -leaf)
            #gcloud storage rm $eventJson
        }
        else {
            # Event is still active- record it so we can wipe out any orphans later.
            # That sounded AWFUL.  jeez.  I meant DELETE any events that aren't ATTACHED to anything. #BanJediHateCrimes
            $validEvents += $e.GoogleEventEmail
            $validGCPProjects += $e.GoogleProjectId
            $validAWSProjects += $e.AWSProjectId
            $validAzureProjects += $e.AzureProjectId
            Send-Update -t 1 -c "$($e.GoogleEventEmail) is still valid with $([Math]::ROUND($maxEventHours - $TimeDiff.TotalHours,1))h remaining."
        }
    }
    $test = @()
    @("OMG DELETE ME","item2","HarnessEvents") | ForEach-Object {
        $item = $_
        $test += [PSCustomObject]@{
            account    = "$item"
            org        = "$item"
            id         = "$item"
            pat        = "$item"
            HarnessEnv = "$item"
        }
    }
    # Cleanup Harness event details
    Remove-HarnessEventDetailsV2 -accounts $test
    # Remove unattached google events
    $eventGroups = Get-UserGroups -allEvents
    foreach ($e in $eventGroups) {
        if ($validEvents -notcontains $e.email) {
            Send-Update -t 1 -c "$($e.email) is no longer valid."
            Remove-EventV2 -email $e.email -id $e.id
        }
    }
    #Remove unattached google projects
    $gcpProjects = Get-GCP-ProjectList
    Send-Update -t 1 -c "$($validGCPProjects.count)/$($gcpProjects.count) valid google project(s)."
    foreach ($project in $gcpProjects) {
        if ($validGCPProjects -notcontains $project.projectId) {
            Send-Update -t 1 -c "Removing project $($project.name) with google id $($project.projectId)"
            Remove-GCPProjectV2 -id $project.projectId
        }
        
    }
    Send-Update -t 1 -c "End event cleanup" 
    exit
}
function Get-RemoveAuto {
    # Run removeauto if cmd line switch used
    if (-not $removeauto) {
        return
    }
    Send-Update -t 1 -c "Running event removal test"
    # Error out with any problems
    $ErrorActionPreference = "Stop"
    Set-Prefs -k "removeauto" -v $true
    Remove-Event
    Send-Update -t 1 -c "End Removal Test"
    exit
}

#Event Functions
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
    if (-not $config.UserEventCount) {
        Send-Update -t 1 -c "User count not entered- skipping adding users."
        return
    }
    $counter = 1
    Get-GoogleAccessToken
    # Get current total
    $startingCount = (Get-GroupMembers -s).memberCount
    $usersNeeded = $config.UserEventCount - $startingCount
    Send-Update -t 1 -c "Group has $startingCount now with goal of $($config.UserEventCount)"
    # Loop to add users if needed
    if ($startingCount -ge $config.UserEventCount) {
        return
    }
    while ($counter -le $usersNeeded) {
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
    Send-Update -t 1 -c "Waiting for all users to be available..."
    $memberCounter = 0
    While ($memberCount -lt $($config.UserEventCount)) {
        $memberCount = (Get-GroupMembers -s).memberCount
        Send-Update -t 1 -c "$memberCount of $($config.UserEventCount)"
        Start-Sleep -s 4
        $memberCounter++
        if ($memberCounter -gt 20) {
            Send-Update -t 2 -c "Something went wrong- users didn't load correctly."
            exit
        }
    }
    Send-Update -t 1 -c "All users added successfully"

}
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
function Get-ClassroomStatus {
    $gcpStatus = Get-DelegateStatus -d gcp
    #GCP Status
    if ($gcpStatus) {
        Set-Prefs -k "GCPDelegateId" -v $gcpStatus.name
        Add-Choice -k "GCPCONFIG" -d "Delete GCP classroom" -c $config.GoogleProject -f Remove-GCP-Project
    }
    else {
        Add-Choice -k "GCPCONFIG" -d "Enable GCP classrom" -c "not enabled" -f New-GCP-Project
    }
    # TODO enable other clouds
    Add-Choice -k "AZCONFIG" -d "Enable Azure classroom" -c "not enabled" -f New-AZResourceGroup
    Add-Choice -k "AWSCONFIG" -d "Enable AWS classroom" -c "not enabled" -f New-AWSProject
}
function Get-Events {
    # Check token status/refresh
    Get-GoogleAccessToken
    # Create an instructor email account if needed
    if (!(Get-User -u $config.InstructorEmail)) {
        New-User -u $config.InstructorEmail
        Send-Update -t 1 -c "Generated your instructor email: $($config.InstructorEmail)"  
    }
    # Clear event list
    $eventList.Clear()
    # Get groups where current email is an instructor
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
    $eventDefault = $eventList | Where-Object default -eq $true
    if ($eventDefault.count -eq 1) {
        Send-Update -t 0 -c "Default event found"
        Set-Prefs -k "GoogleEventName" -v $eventDefault.name
        Set-Prefs -k "GoogleEventId" -v $eventDefault.id
        Set-Prefs -k "GoogleEventEmail" -v $eventDefault.email
        Set-Prefs -k "HarnessOrg" -v "$($config.GoogleEventName.tolower().replace("-","_"))"
    }
    else {
        Send-Update -t 0 -c "NO event found- removing preferences"
        Set-Prefs -k "GoogleEventName" 
        Set-Prefs -k "GoogleEventId"
        Set-Prefs -k "GoogleEventEmail"
        Set-Prefs -k "HarnessOrg" 
    }
}
function Get-GoogleLogin {
    # Use @harness.io email if already logged in
    $myGoogleAccount = Send-Update -t 1 -c "Retrieving local accounts" -r "gcloud auth list --filter=account:'harness.io' --format='value(account)'"
    if ($myGoogleAccount.count -eq 1) {
        Send-Update -t 0 -c "Using current account" -r "gcloud config set account $myGoogleAccount --no-user-output-enabled"
        $currentUser = $myGoogleAccount
    }
    else {
        # Allow @harnessevents.io email for testing- but provide warning this isn't normal for "production"
        $testGoogleAccount = Send-Update -t 0 -c "Didn't find @harness.io email, trying @harnessevents.io" -r "gcloud auth list --filter=account:'harnessevents.io' --format='value(account)'"
        if ($testGoogleAccount.count -eq 1) {
            Send-Update -t 0 -o -c "Using $testGoogleAccount.  Just FYI:Event email should only be used when testing" -r "gcloud config set account $testGoogleAccount --no-user-output-enabled"
            Send-Update -t 2 -c "Used event email $testGoogleAccount.  This should only be done when testing- not in real events."
            $currentUser = $testGoogleAccount
        }
    }
    #Add-Choice -k "GOOGLEUSER" -d "Login/Change Google Account" -c $currentUser -f "Set-GoogleLogin" -t
    if ($currentUser) {
        Set-Prefs -k "InstructorEmail" -v "$($currentUser.split("@")[0])@harnessevents.io"
        Set-Prefs -k "GoogleUser" -v $currentUser
        #Set-GoogleLogin -p $currentUser
        
    }
    else {
        Send-Update -t 2 -c "Sorry, you don't currently have a '@harness.io' email in your logged in accounts."
        Send-Update -t 2 -c "Please login with 'gcloud auth login' and retry."
        exit
    }
    # Sneaking in a couple of headers here to make testing easier :)
    $script:HarnessHeaders = @{
        'x-api-key'    = $config.HarnessPAT
        'Content-Type' = 'application/json'
    }
    $script:HarnessFFHeaders = @{
        'x-api-key'    = $config.HarnessFFToken
        'Content-Type' = 'application/json'
    }
}
function Get-GoogleAccessToken {
    # Check for valid token
    if ($config.GoogleAccessToken -and $config.GoogleAccessTokenTimestamp) {
        # Check if token is over 50m old
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
    # Sneak in grabbing the Harness Feature Flag token and HarnessEvents PATeven though this is a google function. shhhhh!
    if (-not $config.HarnessFFToken) {
        $HarnessFFToken = Send-Update -t 1 -c "Retrieving credentials" -r "gcloud secrets versions access latest --secret='HarnessEventsFF' --project=$($config.AdminProjectId)" 
        Set-Prefs -k "HarnessFFToken" -v $HarnessFFToken
    }
    if (-not $config.HarnessEventsPAT) {
        $HarnessEventsPAT = Send-Update -t 1 -c "Snagging HarnessEvents PAT" -r "gcloud secrets versions access latest --secret='HarnessEventsPAT' --project=$($config.AdminProjectId)"
        Set-Prefs -k "HarnessEventsPAT" -v $HarnessEventsPAT
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
        # Write out auth headers that can be used anywhere
        $script:headers = @{
            "Authorization" = "Bearer $($config.GoogleAccessToken)"
        }
        Send-Update -t 0 -c "Successfully retrieved a new token and timestamp."
    }
    else {
        Send-Update -t 2 -c "Unexpected error while retrieving access token."
    }
    if (-not $headless -and -not $janitorMode) {
        Send-Update -t 1 -c "Switching to original account" -r "gcloud config set account $($config.GoogleUser) --no-user-output-enabled"
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
function Get-GoogleAppToken {
    # Bypass this is running as a deployment test - it won't have the ability to write out a google sheet
    if ($config.headless) {
        return
    }
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
    if (test-path env:GOOGLE_CLOUD_SHELL) {
        Send-Update -t 1 -c "Running Google Cloud Shell, using provided application credentials"
    }
    else {
        #We're not in Google cloud shell, ask permission to login
        Send-Update -t 1 -c "Is it cool if we connect to your Google Drive in order to write a lovely, prepopulated event sheet?"
        Send-Update -t 1 -c "If so, you'll get a popup window next.  Authenticate with your work email, then close the browser tab and return here."
        write-host
        $consentNo = read-host -p "<enter> for yes, 'no' to stop"
        if ($consentNo) {
            Set-Prefs -k "GoogleAppToken" 
            Set-Prefs -k "GoogleAppTokenTimestamp"
            return
        }
        Send-Update -t 1 -c "Clearing application access token" -r "gcloud auth application-default revoke -q"
        Send-Update -t 1 -c "Application access login" -r "gcloud auth application-default login --scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/drive,https://www.googleapis.com/auth/spreadsheets --project=$($config.AdminProjectId) -q"
    }
    $authorizationCode = gcloud auth application-default print-access-token
    if ($authorizationCode) {
        $script:appHeaders = @{
            "Authorization"       = "Bearer $($config.GoogleAppToken)"
            "x-goog-user-project" = $($config.AdminProjectId)
        }
        # Save valid token
        Set-Prefs -k "GoogleAppToken" -v $authorizationCode
        Set-Prefs -k "GoogleAppTokenTimestamp" -v $(Get-date)
        # Save the name of the google account to use later
        Send-Update -t 0 -c "Successfully retrieved a new application token and timestamp."
    }
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
function New-Event {
    # Add new event (essentially a google group with attached email)
    Get-GoogleAccessToken
    while (-not $nameselected) {
        # If this is an automated deployment test, use presets
        if ($config.EventName) {
            $newEvent = $config.EventName
        }
        else {
            $newEvent = read-host -prompt "Name for new event? (lower characters only) <enter> to abort"
        }
        if (-not($newEvent)) {
            return
        }
        # Add user's admin email
        if (!(Get-User -u $config.InstructorEmail)) {
            New-User -u $config.InstructorEmail
            Send-Update -t 1 -c "Generated your instructor email: $($config.InstructorEmail)"  
        }
        $eventName = $newEvent -replace '\W', ''
        $eventName = "event-" + $eventName.tolower()
        $newEmail = $eventName + "@harnessevents.io"
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
    }
    $eventId = Get-GroupKey -g $nameselected
    Set-Prefs -k "GoogleEventId" -v $eventId
    Get-Events
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
    # This does several things:
    # It will delete any existing cloud classrooms
    # It will wipe all event users from the Harness account as well as all google accounts
    # It will delete the event email (completely eliminating the event)
    # It will set all known secrets to a value of 123
    # It will set the "go forward" feature flags as shown in featureflagend.json
    if ($config.headless) {
        Send-Update -t 1 -c "Bypassing event delete confirmation"
    }
    else {
        $confirm = Read-Host -prompt "Confirm you want to remove event: $($config.GoogleEventName)? <y for yes>"
        If ($confirm -ne "y") {
            return
        }
    }
    Get-GoogleAccessToken
    $script:HarnessHeaders = @{
        'x-api-key'    = $config.HarnessPAT
        'Content-Type' = 'application/json'
    }
    $script:HarnessFFHeaders = @{
        'x-api-key'    = $config.HarnessFFToken
        'Content-Type' = 'application/json'
    }
    #Remove Google Project if it exists
    Remove-GCP-Project
    # Remove Harness event
    if ($config.HarnessPAT) {
        $harnessRemoved = Remove-HarnessEventDetails
        if ($harnessRemoved) {
            Send-Update -t 0 -c "Successfully removed Harness config"
        }
        else {
            Send-Update -t 2 -c "Failed to remove Harness Config.  It's not safe to delete google event."
            exit
        }
    }
    # Remove google user accounts
    Send-Update -t 1 -c "Deleting @harnessevents.io google email accounts"
    $members = Get-GroupMembers -s
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
            Send-Update -t 2 -c "Something went wrong- @harnessevents.io users didn't fully delete."
            exit
        }
    }
    Send-Update -t 0 -c "Successfully deleted users"
    $groupUri = "https://admin.googleapis.com/admin/directory/v1/groups/$($config.GoogleEventId)"
    $GroupCheckUri = "https://admin.googleapis.com/admin/directory/v1/groups?domain=harnessevents.io&query=email=$($config.GoogleEventEmail)"
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
    if ($config.removeauto -or $config.HarnessAccount -eq "HarnessEvents") {
        Remove-Organization
    }
    # If we're auto-removing, delete the sensitive parts only and save the rest
    if ($config.RemovalTriggered) {
        Set-Prefs -k "HarnessPAT"
        Set-Prefs -k "HarnessFFToken"
        Set-Prefs -k "HarnessEventsPAT"
        Set-Prefs -k "GoogleAccessToken"
        Set-Prefs -k "ServiceAccountKey"
        Set-Prefs -k "GoogleAppToken"
    }
    else {
        Set-Prefs -k "HarnessOrg"
        Set-Prefs -k "HarnessAccountId"
        Set-Prefs -k "HarnessAccount"
        Set-Prefs -k "UserEventCount"
        Set-Prefs -k "UseGoogleClassroom"
        Set-Prefs -k "UseAzureClassroom"
        Set-Prefs -k "UseAWSClassroom"
        Set-Prefs -k "GoogleEventEmail"
        Set-Prefs -k "GoogleEventId"
        Set-Prefs -k "GoogleEventName"
        Set-Prefs -k "HarnessPAT"
        Get-Events
    }
}
function Remove-EventV2 {
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
function Save-Event {
    $datePrefix = $(Get-Date -Uformat "%Y-%m")
    $fileName = $config.GoogleUser.split("@")[0] + "-" + $config.EventName + ".json"
    gcloud storage cp boxofscraps.ps1.conf gs://harnesseventsdata/events/open/$datePrefix-$fileName
}
function Save-EventDetails {
    $members = Get-GroupMembers | select-object -property role, email | sort-object -property role -Des
    $attendeeCount = $members.count
    $members | Add-Member -MemberType NoteProperty -Name "password" -Value ""
    $members | Add-Member -MemberType NoteProperty -Name "HarnessLink" -Value ""
    $members | Add-Member -MemberType NoteProperty -Name "LabLink" -Value ""
    # Create array of arrays suitable for dropping into googley sheet
    $exportArray = @()
    $exportArray += ,@("Open this in an incognito window!")
    $exportArray += ,@($config.GoogleEventName)
    $exportArray += ,@(" ")
    $exportArray += ,@("    Class Email Address    ","  Class Password  ","  Direct Project Link  ","  Lab Guide  ","  Your Name  ","  Where are you from?  ","  Vacations-Hot or Cold?  ")
    foreach ($member in $members) {
        $cleanProject = ($member.email.split("@")[0] -replace '\W', '').tolower()
        if ($member.role -eq "MEMBER") {
            $member.role = "Attendee"
            $member.password = "Harness!"
            $member.HarnessLink = "https://app.harness.io/ng/account/$($config.HarnessAccountId)/module/cd/orgs/$($config.HarnessOrg)/projects/$($cleanProject)/pipelines"
            $harnessLink = '=HYPERLINK("' + $($member.HarnessLink) + '","Project Link")'
            $member.LabLink = "https://suchcodewow.io/harness?account=$($config.HarnessAccountId)&org=$($config.HarnessOrg)&project=$($cleanProject)"
            $labLink = '=HYPERLINK("' + $($member.LabLink) + '","Lab Guide")'
            $exportArray += ,@($member.email, $member.password, $harnessLink, $labLink)
        }
        else {
            $member.role = "Instructor"
            $exportArray += ,@($member.email)
        }
    }
    # If there's a google project, generate links for it
    if ($config.GoogleProjectId) {
        $exportArray += ,@(" ")
        $exportArray += ,@("Event Google Project Links")
        $googleKubernetesLink = '=HYPERLINK("https://console.cloud.google.com/kubernetes/list/overview?project=' + $config.GoogleProjectId + '","Kubernetes")'
        $googleArtifactsLink = '=HYPERLINK("https://console.cloud.google.com/artifacts?project=' + $config.GoogleProjectId + '","Artifact Registry")'
        $googleRunLink = '=HYPERLINK("https://console.cloud.google.com/run?project' + $config.GoogleProjectId + '","Cloud Run")'
        $exportArray += ,@($googleKubernetesLink,$googleArtifactsLink,$googleRunLink)
        $GoogleDetails = "`r`n"
        $GoogleDetails += "Google Kubernetes Overview,https://console.cloud.google.com/kubernetes/list/overview?project=$($config.GoogleProjectId)`r`n"
        $GoogleDetails += "Google Artifact Registry,https://console.cloud.google.com/artifacts?project=$($config.GoogleProjectId)`r`n"
        $GoogleDetails += "Google Cloud Run,https://console.cloud.google.com/run?project=$($config.GoogleProjectId)`r`n"
    }
    # TODO Generate links for AWS
    # TODO Generate links for Azure
    # Check if we have consent to write out a google worksheet
    if (-not $config.GoogleAppToken) {
        $members | Format-Table
        $members | Export-Csv "$($config.GoogleEventName).csv"
        $GoogleDetails | Add-Content -Path "$($config.GoogleEventName).csv"
        Send-Update -t 1 -c "Exported --> $($config.GoogleEventName).csv"
        return
    }
    # Get ID of HarnessEvents shared drive
    $uriDrive = "https://www.googleapis.com/drive/v3/drives?supportsAllDrives=true&q=name='HarnessEvents'"
    $drive = Invoke-RestMethod -Method 'GET' -uri $uriDrive -Headers $appHeaders -ContentType "application/json"
    # Get ID of instructor classrooms folder
    $uriEventsFolder = "https://www.googleapis.com/drive/v3/files?supportsAllDrives=true&includeItemsFromAllDrives=true&corpora=drive&driveId=$($drive.drives.id)&q=mimeType='application/vnd.google-apps.folder' and name='instructor classrooms'"
    $eventsFolder = Invoke-RestMethod -Method 'GET' -uri $uriEventsFolder -Headers $appHeaders -ContentType "application/json"
    # Check if HarnessEvents folder already exists in current user's googley drive- create if needed
    $uri = "https://www.googleapis.com/drive/v3/files?supportsAllDrives=true&includeItemsFromAllDrives=true&corpora=drive&driveId=$($drive.drives.id)&q=mimeType='application/vnd.google-apps.folder' and name='" + $($config.GoogleUser) + "' and '" + $eventsFolder.files.id + "' in parents"
    Send-Update -t 0 -c "uri to check for google folder: $uri"
    $response = invoke-restmethod -Method 'GET' -uri $uri -Headers $appHeaders -ContentType "application/json"
    if ($response.files) {
        Send-Update -t 0 -c "$($config.GoogleUser) Google Drive folder already exists- skipping creation"
        $parentFolder = $response.files.id
    }
    else {
        $bodyFolder = @{
            "name"     = $config.GoogleUser
            "mimeType" = "application/vnd.google-apps.folder"
            "parents"  = @(
                $eventsFolder.files.id
            )
        } | ConvertTo-Json
        $folder = invoke-restmethod -Method 'POST' -uri $uri -Headers $appHeaders -body $bodyFolder -ContentType "application/json"
        Send-Update -t 0 -c "Created Google Drive folder: $($config.GoogleUser)"
        $parentFolder = $folder.id
    }
    if (-not $parentFolder) {
        Send-Update -t 2 -c "Failed to create or obtain HarnessEvents Google Folder- skipping google sheet create."
        return
    }
    # We have a valid parent folder- delete old google sheet if present
    $uriFileExists = "https://www.googleapis.com/drive/v3/files?supportsAllDrives=true&includeItemsFromAllDrives=true&corpora=drive&driveId=$($drive.drives.id)&q='$($parentFolder)' in parents and name='$($config.GoogleEventName)'"
    $responseFileExists = invoke-restmethod -Method 'GET' -headers $appHeaders -uri $uriFileExists
    if ($responseFileExists.files.id) {
        foreach ($fileId in $responseFileExists.files.id) {
            # $fileId = $responseFileExists.files.id
            $uriDelete = "https://www.googleapis.com/drive/v3/files/$($fileId)?supportsAllDrives=true"
            Send-Update -t 0 -c "delete uri: $uriDelete"
            Invoke-RestMethod -method 'Delete' -uri $uriDelete -headers $appHeaders
            Send-Update -t 0 -c "Deleted old file: $fileId"
        }
    }
    $bodyFile = @{
        "name"     = $($config.GoogleEventName)
        "mimeType" = "application/vnd.google-apps.spreadsheet"
        parents    = @(
            $parentFolder
        )
    } | ConvertTo-Json
    $responseSheets = invoke-restmethod -Method 'POST' -uri $uri -Headers $appHeaders -body $bodyFile -ContentType "application/json"
    if (-not $responseSheets.id) {
        Send-Update -t 2 -c "Failed to create $($config.GoogleEventName) Google Sheet"
        return
    }
    else {
        $fileId = $responseSheets.id
    }
    # Clear data from spreadsheet
    $uriClear = "https://sheets.googleapis.com/v4/spreadsheets/$($fileId)/values/A1:Z1000:clear"
    invoke-restmethod -Method 'POST' -uri $uriClear -Headers $appHeaders | Out-Null
    # Add Data to spreadsheet
    $uriSheet = "https://sheets.googleapis.com/v4/spreadsheets/$fileId/values/A1?valueInputOption=USER_ENTERED"
    $bodySheet = @{
        "values" = $exportArray
    } | ConvertTo-Json
    invoke-restmethod -Method 'PUT' -uri $uriSheet -Headers $appHeaders -body $bodySheet -ContentType "application/json" | Out-null
    # Autosize Columns
    $uriResize = "https://sheets.googleapis.com/v4/spreadsheets/$($fileId):batchUpdate"
    $bodyResize = @{
        "requests" = @(
            ,@{
                "repeatCell" = @{
                    "range"  = @{
                        "sheetId"       = 0
                        "startRowIndex" = 3
                        "endRowIndex"   = 4
                    }
                    "cell"   = @{
                        "userEnteredFormat" = @{
                            "backgroundColor"     = @{
                                "red"   = 0.471
                                "green" = 0.565
                                "blue"  = 0.612
                            }
                            "horizontalAlignment" = "CENTER"
                            "textFormat"          = @{
                                "foregroundColor" = @{
                                    "red"   = 1.0
                                    "green" = 1.0
                                    "blue"  = 1.0
                                }
                                "fontSize"        = 12
                                "bold"            = $true
                            }
                        }
                    }
                    "fields" = "userEnteredFormat(backgroundColor,textFormat,horizontalAlignment)"
                }
            }
            ,@{
                "repeatCell" = @{
                    "range"  = @{
                        "sheetId"          = 0
                        "startRowIndex"    = 5 + $attendeeCount
                        "endRowIndex"      = 6 + $attendeeCount
                        "startColumnIndex" = 0
                        "endColumnIndex"   = 1
                    }
                    "cell"   = @{
                        "userEnteredFormat" = @{

                            "textFormat" = @{
                                "foregroundColor" = @{
                                    "red"   = 1.0
                                    "green" = 0.671
                                    "blue"  = 0.251
                                }
                                "fontSize"        = 12
                                "bold"            = $true
                            }
                        }
                    }
                    "fields" = "userEnteredFormat(textFormat,horizontalAlignment)"
                }
            }
            ,@{
                "autoResizeDimensions" = @{
                    "dimensions" = @{
                        "sheetId"    = 0
                        "dimension"  = "COLUMNS"
                        "startIndex" = 0
                        "endIndex"   = 10
                    }
                }
            }
        )
    } | ConvertTo-Json -Depth 20
    invoke-restmethod -Method 'POST' -uri $uriResize -body $bodyResize -Headers $appHeaders -ContentType "application/json" | out-Null
    Send-Update -t 1 -c "-------------------------------------------------------"
    Send-Update -t 1 -c "Your event has been updated! Direct workshop sheet link:  https://docs.google.com/spreadsheets/d/$($fileId)"
    Send-Update -t 1 -c "Or open your Google Drive and navigate to: <your drive>/HarnessEvents/$($config.GoogleEventName)"
    Set-Prefs -k "EventLink" -v "https://docs.google.com/spreadsheets/d/$($fileId)"
    Save-Event
}
function Set-Event {
    Get-Events
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
        Set-Prefs -k "GoogleEventId" -v $eventSelected.id
        Get-Events
    }
}
function Set-EventUsers {
    while (-not $usersToAdd) {
        $userCount = read-host -prompt "How many attendees will $($config.GoogleEventName) have include yourself and other instructors? <enter> to abort"
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
    Set-Prefs -k "UserEventCount" -v $usersToAdd
}
function Sync-Event {
    Get-GoogleApiAccessToken
    Get-Events
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

#Harness Functions
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
function Add-Delegate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $delegatePrefix #expecting gcp/az/aws
    )
    $delegateName = $delegatePrefix + "-delegate-" + $($config.HarnessOrg.replace("_","-"))
    #Check if there was an existing delegate
    Send-Update -t 1 -c "Checking for existing delegate"
    $delegateStatus = Get-DelegateStatus
    $delegateAvailable = $delegateStatus | where-object { $_.name -eq $delegateName }
    if ($delegateAvailable) {
        Send-Update -t 1 -c "$delegateName already exists and is connected. Skipping creation."
        return
    }
    # Check for disconnected delegate by tag lookup
    $uriTags = "https://app.harness.io/ng/api/delegate-group-tags/delegate-groups?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
    $bodyTags = @{
        "tags" = @(
            $delegateName
        )
    } | Convertto-Json
    try {
        $response = Invoke-RestMethod -method 'POST' -uri $uriTags -headers $HarnessHeaders -body $bodyTags -ContentType 'application/json'
    }
    catch {
        Send-update -t 0 -c "no delegate exists."
    }
    if ($response.resource) {
        Send-Update -t 1 -c "Deleting disconnected/old delegate by id: $($response.resource.identifier)"
        Remove-Delegate -delegateId $response.resource.identifier
    }
    Send-Update -t 0 -c "Current delegate found: $delegateStatus"
    if ($delegateStatus -and $delegateStatus.name.contains($delegateName)) {
        #Remove-Delegate -delegatePrefix $delegatePrefix
        Send-Update -t 1 -c "Delegate: $delegateName already exists. Skipping create."
        return
    }
    Send-Update -t 1 -c "Get $delegateName Delegate Config" -r "Get-DelegateConfig -d $delegateName"
    Send-Update -t 1 -o -c "Apply $delegateName delegate yaml" -r "kubectl apply -f $delegateName.yaml"
    if (test-path -Path "$delegateName.yaml") { Remove-Item "$delegateName.yaml" }
    $counter = 0
    Do {
        Send-Update -t 1 -c "Waiting for delegate to be available..."
        $delegateStatus = Get-DelegateStatus
        $delegateAvailable = $delegateStatus | where-object { $_.name -eq $delegateName }
        $counter++
        if ($counter -ge 10) {
            Send-Update -t 2 -c "Sorry... delegate did not load correctly."
            exit
        }
        Start-sleep -s 20
    } While (-not $delegateAvailable)
    Send-Update -t 1 -c "$DelegatePrefix Delegate is connected and ready!"
}
function Add-Filter {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $filterType, #Connector, Template, Secret known so far (api reference is blank- fun!)
        [string]
        $name
    )
    # Need to use a combination of documented and undocumented API's here.  It's ok though.  I'm all cried out at this point.
    # The API can't hurt me any more.
    Switch ($filterType) {
        "Connector" {
            $uri = "https://app.harness.io/ng/api/filters?accountIdentifier=$($config.HarnessAccountId)"
        }
        "Template" {
            $uri = "https://app.harness.io/template/api/filters?accountIdentifier=$($config.HarnessAccountId)"
        }
        default {
            Send-Update -t 0 -c "$filterType is unsupported. Can't add $name"
        }
    }
    $body = @{
        "name"             = $name
        "identifier"       = $name
        "orgIdentifier"    = $config.HarnessOrg
        "filterVisibility" = "EveryOne"
        "filterProperties" = @{
            "connectorNames"       = @()
            "connectorIdentifiers" = @()
            "filterType"           = $filterType
            "tags"                 = @{
                $name = ""
            }
        }
    } | ConvertTo-Json -Depth 5
    $body1 = @{
        filterVisibility = "EveryOne"
        identifier       = "gcp"
        orgIdentifier    = "event_builder"
        name             = "gcp"
        filterProperties = @{
            tags                 = @{
                gcp = ""
            }
            connectorNames       = @()
            connectorIdentifiers = @()
            filterType           = "Template"
        }
    } | ConvertTo-Json -Depth 5
    $templateheaders = @{
        'x-api-key' = $config.HarnessPAT
    }
    Try {
        Invoke-RestMethod -uri $uri -body $body -Method 'POST' -headers $templateheaders -ContentType "application/json" | Out-null
    }
    Catch {
        $errorResponse = $_ | Convertfrom-Json
        if ($errorResponse.code -eq "DUPLICATE_FIELD") {
            Send-Update -t 1 -c "Filter $name already exists in org $($config.HarnessOrg)."
        }
        else {
            Send-Update -t 2 -c "uri attempted was: $uri"
            Send-Update -t 2 -c "body was: $body"
            Send-Update -t 2 -c "Failed to create filter with error: $errorResponse"
            write-host $body1
            exit
        }  
    }
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
function Add-HarnessEventDetails {
    # This step does a bunch of things right now (maybe break it down?)
    # It will:
    #   enable the feature flags at ./harnesseventsdata/config/featureflagstart.json
    #   add filters listed at ./harnesseventsdata/config/filters.json
    #   enable google-auth in oauth settings and create an attendee role
    #   load all secrets starting with 'org' from google secret manager
    #   load all templates found in ./harnesseventsdata/OrgTemplates/*.yaml
    #   add the organization for the chosen event, add projects for everyone, and add users to the attendee role

    # Add needed flags
    $featureFlagsStart = Get-Content -path ./harnesseventsdata/config/featureflagsstart.json | Convertfrom-Json
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
    #Enable Google Auth for attendee access & Org level bits
    Enable-GoogleAuth
    Add-Organization
    # Add filters to make it easier to find stuff
    $filters = Get-Content -path ./harnesseventsdata/config/filters.json | Convertfrom-Json
    foreach ($filterObject in $filters.psobject.Properties.name) {
        foreach ($filter in $filters.$filterObject) {
            #write-host "type $filterObject name $filter"
            Add-Filter -filterType $filterObject -name $filter
        }
    }
    # Add secrets from google secret manager
    Add-OrgSecrets
    # Add everything in order from the 'org' folder
    $OrgContent = Get-Childitem -path ./harnesseventsdata/org -attributes D
    foreach ($folder in $OrgContent) {
        Add-OrgYaml -YamlFolder "$folder/*.yaml"
    }
    # Add-OrgYaml -YamlFolder "./harnesseventsdata/OrgEnvironments/*.yaml"
    # Add-OrgYaml -YamlFolder "./harnesseventsdata/OrgTemplates/*.yaml"
    Add-Policies
    Add-AttendeeRole
    $attendees = Get-GroupMembers
    $attendees += [PSCustomObject]@{"email" = $config.GoogleUser; "role" = "OWNER" }
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
    # Check if user already exists
    $userExists = Get-HarnessUser -e $userEmail
    if ($userExists) {
        Send-Update -t 1 -c "$userEmail already exists.  Skipping create."
    }
    else {
        # Create user account
        do {
            # Loop until valid Org User
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
            $activeUser = Get-HarnessUser -e $userEmail
            if (-not $activeUser) {
                # Make sure the stupid slow flag was active to automatically add user to 'active'
                $pendingUser = Get-PendingUser -e $userEmail
                if ($pendingUser) {
                    Send-Update -t 1 -c "Flag wasn't ready- removing user invite for $userEmail"
                    Remove-PendingUser -inviteId $pendingUser.id
                }
                else {
                    Send-Update -t 1 -c "Waiting for $userEmail to be available"
                }
                Start-Sleep -s 2
            }
        } until ($activeUser)
        # Add user at Project level
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
       
        Send-Update -t 1 -c "Added $userEmail to $projectName project admin and $($config.HarnessOrg) attendeeRole."
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
            Send-Update -t 2 -c "Failed to create organization with error: $errorResponse"
            exit
        }
    }
}
function Add-OrgSecrets {
    # Load all secrets from administration secret manager
    $orgSecrets = Send-Update -t 1 -c "Get secrets to install" -r "gcloud secrets list --project=$($config.AdminProjectId) --filter='name ~ org*' --format='value(NAME)'"

    foreach ($secret in $orgSecrets) {
        #if (-not $secret.substring(0,3) -eq "org") { break }
        $secretValue = gcloud secrets versions access latest --secret=$secret --project=$($config.AdminProjectId)
        $ContentType = "application/json"
        $secretID = $secret.substring(3)
        $secretName = $secretID.replace("_"," ")
        $templateheaders = @{
            'x-api-key' = $($config.HarnessPAT)
        }
        $body = @{
            secret = @{
                type          = "SecretText"
                name          = $secretName
                identifier    = $secretID
                orgIdentifier = $($config.HarnessOrg)
                spec          = @{
                    errorMessageForInvalidYaml = "string"
                    secretManagerIdentifier    = "org.harnessSecretManager"
                    type                       = "SecretTextSpec1"
                    valueType                  = "Inline"
                    value                      = $secretValue
                }
            }
        } | Convertto-Json
        $uri = "https://app.harness.io/ng/api/v2/secrets?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)&privateSecret=false"
        Try {
            Send-Update -t 1 -c "Adding/Updating secret: $secretID"
            Invoke-RestMethod -uri $uri -Method 'POST' -headers $templateheaders -ContentType $contentType -body $body | Out-Null
        }
        Catch {
            $errorResponse = $_ | Convertfrom-Json
            if ($errorResponse.message.contains("already exists")) {
                Send-Update -t 0 -c "Secret: $secretID already exists."
            }
            else {
                Send-Update -t 2 -c "Failed to create template: $templateId  with error: $errorResponse.message"
                Send-Update -t 2 -c "Uri was: $uri"
                Send-Update -t 2 -c "Body was: $body"
                #exit
            }   
        }
    }
}
function Add-OrgYaml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $YamlFolder
    )
    # This is currently a bit complex.  There are several yaml types in Harness that use aaaalllllmost the same
    # api structure.  Right now this function is identifying the type from the first line of yaml and then handling
    # multiple scenarios.
    $OrgTemplates = Get-ChildItem -path $YamlFolder
    foreach ($yaml in $OrgTemplates) {
        $modifiedTemplate = ""
        $templateId = (split-path $yaml -Leaf).split(".")[0]
        $templateName = $templateId.Replace("_"," ")
        $template = Get-Content -path $yaml
        # There are multiple endpoints for essentially the same yaml.  Identify the type when it appears in the yaml
        # then setup the API requirements that team thought would be fun the day they designed their endpoint in a vacuum.
        $templateFirstLine = $template[0].trim()
        switch ($templateFirstLine) {
            "template:" {
                $modifiedTemplate += "$templateFirstLine`r`n"
                $modifiedTemplate += "  name: $templateName`r`n"
                $modifiedTemplate += "  identifier: $templateId`r`n"
                $modifiedTemplate += "  versionLabel: ""1""`r`n"
                $modifiedTemplate += "  orgIdentifier: $($config.HarnessOrg)`r`n"
                $uri = "https://app.harness.io/template/api/templates?storeType=INLINE&accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
                $contentType = "application/json"
                $templateType = "template"
            }
            "connector:" {
                $modifiedTemplate += "$templateFirstLine`r`n"
                $modifiedTemplate += "  name: $templateName`r`n"
                $modifiedTemplate += "  identifier: $templateId`r`n"
                $modifiedTemplate += "  versionLabel: ""1""`r`n"
                $modifiedTemplate += "  orgIdentifier: $($config.HarnessOrg)`r`n"
                $uri = "https://app.harness.io/ng/api/connectors?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
                $contentType = "text/yaml"
                $templateType = "connector"
            }
            "service:" {
                $modifiedTemplate += "$templateFirstLine`r`n"
                $modifiedTemplate += "  name: $templateName`r`n"
                $modifiedTemplate += "  identifier: $templateId`r`n"
                $modifiedTemplate += "  orgIdentifier: $($config.HarnessOrg)`r`n"
                $uri = "https://app.harness.io/ng/api/servicesV2?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
                $contentType = "application/json"
                $templateType = "service"
            }
            "environment:" {
                $modifiedTemplate += "$templateFirstLine`r`n"
                $modifiedTemplate += "  name: $templateName`r`n"
                $modifiedTemplate += "  identifier: $templateId`r`n"
                $modifiedTemplate += "  orgIdentifier: $($config.HarnessOrg)`r`n"
                $uri = "https://app.harness.io/ng/api/environmentsV2?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
                $contentType = "application/json"
                $templateType = "environment"
            }
            "infrastructureDefinition:" {
                $modifiedTemplate += "$templateFirstLine`r`n"
                $modifiedTemplate += "  name: $templateName`r`n"
                $modifiedTemplate += "  identifier: $templateId`r`n"
                $modifiedTemplate += "  orgIdentifier: $($config.HarnessOrg)`r`n"
                $uri = "https://app.harness.io/ng/api/infrastructures?accountIdentifier=$($config.HarnessAccountId)"
                $contentType = "application/json;charset=utf-8"
                $templateType = "infrastructureDefinition"
            }
            default {
                Send-Update -t 0 -c "Unknown template type $templateId with first line of $templateFirstLine"
                break
            }
        }
        # Load all remaining lines except the ones updated above.
        foreach ($line in $template | Select-Object -skip 1) {
            $addThisLine = $true
            # Ignore any of these situations
            if ($line.length -ge 7 -and $line.substring(0,7) -eq "  name:") {
                $addThisLine = $false
            }
            if ($line.length -ge 13 -and $line.substring(0,13) -eq "  identifier:") {
                $addThisLine = $false
            }
            if ($line.length -ge 15 -and $line.substring(0,15) -eq "  versionLabel:") {
                $addThisLine = $false
            }
            if ($line.length -ge 16 -and $line.substring(0,16) -eq "  orgIdentifier:") {
                $addThisLine = $false
            }
            if ($line.length -ge 20 -and $line.substring(0,20) -eq "  projectIdentifier:") {
                $addThisLine = $false
            }
            if ($addThisLine) {
                $modifiedTemplate += "$line`r`n"
            }
        }
        $templateheaders = @{
            'x-api-key' = $config.HarnessPAT
        }
        # It's insane, but some API calls require duplicating values both in yaml and in body (????).. 
        # so add more duplicate unecessary logic... and then have a little cry.
        switch ($templateFirstLine) {
            "service:" {
                $body = @{
                    "name"          = $templateName
                    "identifier"    = $templateId
                    "orgIdentifier" = $config.HarnessOrg
                    "yaml"          = $modifiedTemplate
                } | Convertto-Json
            }
            "environment:" {
                $body = @{
                    "name"          = $templateName
                    "identifier"    = $templateId
                    "orgIdentifier" = $config.HarnessOrg
                    "type"          = "Production"
                    "yaml"          = $modifiedTemplate
                } | Convertto-Json
            }
            "infrastructureDefinition:" {
                $body = @{
                    "yaml" = $modifiedTemplate
                } | ConvertTo-Json
            }
            default {
                $body = $modifiedTemplate
            }
        }
        Try {
            Send-Update -t 1 -c "Adding/Updating org $($templateType): $templateId"
            Invoke-RestMethod -uri $uri -body $body -Method 'POST' -headers $templateheaders -ContentType $contentType | Out-null
        }
        Catch {
            # Generates a System.Management.Automation.ErrorRecord
            if ($_.Exception.Response.StatusCode.value__ -ne 401) {
                $errorResponse = $_ | Convertfrom-Json
                if ($errorResponse.message.contains("already exists")) {
                    Send-Update -t 0 -c "Template: $templateId already exists."
                }
                else {
                    Send-Update -t 2 -c "Failed to create template: $templateId with error: $errorResponse.message"
                    Send-Update -t 0 -c "URI: $uri"
                    Send-Update -t 0 -c "ContentType: $contentType"
                    Send-Update -t 0 -c "Headers: $($templateheaders | Select-Object -Property *)"
                    Send-Update -t 0 -c "template yaml:"
                    Send-Update -t 0 -c $body
                }  
            }
            else {
                Send-Update -t 2 -c "Failed to create template: $templateId. 401: $_)"
                Send-Update -t 0 -c "URI: $uri"
                Send-Update -t 0 -c "ContentType: $contentType"
                Send-Update -t 0 -c "Headers: $($templateheaders | Select-Object -Property *)"
                Send-Update -t 0 -c "template yaml:"
                Send-Update -t 0 -c $body
            }
        }
    }
}
function Add-Policies {
    # Install all policies
    $uri = "https://app.harness.io/pm/api/v1/policies?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
    $orgPolicies = Get-ChildItem -path ./harnesseventsdata/Policies/*.policy 
    foreach ($policy in   $orgPolicies) {
        $policyId = (split-path $policy -Leaf).split(".")[0]
        $policyName = $policyId.Replace("_"," ")
        $policyContent = gcloud storage cat $policy | Out-String
        $body = @{
            "name"       = $policyName
            "identifier" = $policyId
            "rego"       = $policyContent
        } | ConvertTo-Json
        Try {
            Invoke-Restmethod -method 'POST' -uri $uri -body $body -ContentType "application/json" -headers $HarnessHeaders | Out-Null
        }
        Catch {
            # Generates a System.Management.Automation.ErrorRecord
            if ($_.Exception.Response.StatusCode.value__ -ne 401) {
                $errorResponse = $_ | Convertfrom-Json
                if ($errorResponse.message.contains("policy identifier must be unique")) {
                    Send-Update -t 0 -c "Policy: $policyId already exists."
                }
                else {
                    Send-Update -t 2 -c "Failed to create policy: $policyId with error: $errorResponse.message"
                    Send-Update -t 0 -c "URI: $uri"
                    Send-Update -t 0 -c "ContentType: $contentType"
                    Send-Update -t 0 -c "Headers: $($templateheaders | Select-Object -Property *)"
                    Send-Update -t 0 -c "template yaml:"
                    Send-Update -t 0 -c $body
                }  
            }
            else {
                Send-Update -t 2 -c "Failed to create policy: $policyId. 401: $_)"
                Send-Update -t 0 -c "URI: $uri"
                Send-Update -t 0 -c "ContentType: $contentType"
                Send-Update -t 0 -c "Headers: $($templateheaders | Select-Object -Property *)"
                Send-Update -t 0 -c "template yaml:"
                Send-Update -t 0 -c $body
            }
        }
    }
    # Then install policysets using ID's of created policies
    $uriPolicyset = "https://app.harness.io/gateway/pm/api/v1/policysets?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
    $policySets = Get-ChildItem -path ./harnesseventsdata/Policies/*.policyset
    foreach ($policyset in $policySets) {
        $setId = (split-path $policyset -Leaf).split(".")[0]
        $setName = $setId.Replace("_"," ")
        $setContent = gcloud storage cat $policyset | Convertfrom-Json
        $setBody = @{
            "name"       = $setName
            "identifier" = $setId
            "action"     = "onsave"
            "enabled"    = $false
            "type"       = "pipeline"
            "policies"   = @(
                $setContent
            )
        } | ConvertTo-Json
        Try {
            Invoke-Restmethod -method 'POST' -uri $uriPolicyset -body $setBody -ContentType "application/json" -headers $HarnessHeaders | Out-Null
        }
        Catch {
            # Generates a System.Management.Automation.ErrorRecord
            if ($_.Exception.Response.StatusCode.value__ -ne 401) {
                $errorResponse = $_ | Convertfrom-Json
                if ($errorResponse.message.contains("policy set identifier must be unique")) {
                    Send-Update -t 0 -c "Policy set: $setId already exists."
                }
                else {
                    Send-Update -t 2 -c "Failed to create policy set: $setId with error: $errorResponse.message"
                    Send-Update -t 0 -c "URI: $uri"
                    Send-Update -t 0 -c "ContentType: $contentType"
                    Send-Update -t 0 -c "Headers: $($templateheaders | Select-Object -Property *)"
                    Send-Update -t 0 -c "template yaml:"
                    Send-Update -t 0 -c $body
                }  
            }
            else {
                Send-Update -t 2 -c "Failed to create policy set: $setId. 401: $_)"
                Send-Update -t 0 -c "URI: $uri"
                Send-Update -t 0 -c "ContentType: $contentType"
                Send-Update -t 0 -c "Headers: $($templateheaders | Select-Object -Property *)"
                Send-Update -t 0 -c "template yaml:"
                Send-Update -t 0 -c $body
            }
        }
    }
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
            Send-Update -t -2 -c "uri attempted was: $uri"
            Send-Update -t -2 -c "body was: $body"
            Send-Update -t 2 -c "Failed to create organization with error: $errorResponse"
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
function Add-SecretJson {
    # Add Json Secret File
    $uri = "https://app.harness.io/ng/api/v2/secrets/files?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
    $spec = @{
        secret = @{
            type          = 'SecretFile'
            name          = $secretName
            identifier    = $secretID
            orgIdentifier = $($config.HarnessOrg)
            spec          = @{
                secretManagerIdentifier = "org.harnessSecretManager"
            }
        }
    } | ConvertTo-Json

    $multipartContent = [System.Net.Http.MultipartFormDataContent]::new()

    $stringHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
    $stringHeader.Name = "spec"
    $StringContent = [System.Net.Http.StringContent]::new($spec)
    $StringContent.Headers.ContentDisposition = $stringHeader
    $multipartContent.Add($stringContent)
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
}
function Add-Variables {
    # Define the variables here that we want to use
    $variables = @(
        @{"name" = "google_project"; "value" = $config.GoogleProjectId },
        @{"name" = "google_region";"value" = $config.GoogleRegion },
        @{"name" = "google_resource_id";"value" = $config.GoogleResourceID }
    )
    # Install all variables at the org level.
    foreach ($variable in $variables) {
        $uri = "https://app.harness.io/ng/api/variables?accountIdentifier=$($config.HarnessAccountId)"
        $body = @{
            variable = @{
                name          = $variable.name.replace("_"," ")
                identifier    = $variable.name
                orgIdentifier = $($config.HarnessOrg)
                description   = ""
                type          = "String"
                spec          = @{
                    valueType     = "FIXED"
                    fixedValue    = $variable.value ?? "replaceme"
                    allowedValues = @()
                    defaultValue  = ""
                }
            }
        } | ConvertTo-Json -Depth 5
        Send-Update -t 1 -c "Adding/Updating variable $($variable.name)"
        Try {
            Invoke-RestMethod -uri $uri -body $body -Method 'POST' -headers $HarnessHeaders | Out-null
        }
        Catch {
            # Generates a System.Management.Automation.ErrorRecord
            if ($_.Exception.Response.StatusCode.value__ -ne 401) {
                $errorResponse = $_ | Convertfrom-Json
                if ($errorResponse.message.contains("already exists")) {
                    Send-Update -t 0 -c "Template: $templateId already exists."
                }
                else {
                    Send-Update -t 2 -c "Failed to create variable: $($variable.name)"
                    Send-Update -t 0 -c "URI: $uri"
                    Send-Update -t 0 -c "ContentType: $contentType"
                    Send-Update -t 0 -c "Headers: $($templateheaders | Select-Object -Property *)"
                    Send-Update -t 0 -c "body:"
                    Send-Update -t 0 -c $body
                }  
            }
            else {
                Send-Update -t 2 -c "Failed to create template: $templateId. 401: $_)"
                Send-Update -t 0 -c "URI: $uri"
                Send-Update -t 0 -c "ContentType: $contentType"
                Send-Update -t 0 -c "Headers: $($templateheaders | Select-Object -Property *)"
                Send-Update -t 0 -c "template yaml:"
                Send-Update -t 0 -c $body
            }
        }
    }

}
function Clear-OrgSecrets {
    # Set all Harness provided secrets to '123' after event
    $orgSecrets = Send-Update -t 1 -c "Get secrets to clear" -r "gcloud secrets list --filter='name ~ org*' --project=$($config.AdminProjectId) --format='value(NAME)'"
    foreach ($secret in $orgSecrets) {
        $secretValue = "123"
        $ContentType = "application/json"
        $secretID = $secret.substring(3)
        $secretName = $secretID.replace("_"," ")
        $templateheaders = @{
            'x-api-key' = $($config.HarnessPAT)
        }
        $body = @{
            secret = @{
                type          = "SecretText"
                name          = $secretName
                identifier    = $secretID
                orgIdentifier = $($config.HarnessOrg)
                spec          = @{
                    errorMessageForInvalidYaml = "string"
                    secretManagerIdentifier    = "org.harnessSecretManager"
                    type                       = "SecretTextSpec1"
                    valueType                  = "Inline"
                    value                      = $secretValue
                }
            }
        } | Convertto-Json
        $uri = "https://app.harness.io/ng/api/v2/secrets/$($secretID)?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)&privateSecret=false"
        Send-Update -t 1 -c "Clearing secret: $secretID"
        Try {
            Invoke-RestMethod -uri $uri -Method 'PUT' -headers $templateheaders -ContentType $contentType -body $body | Out-Null
        }
        Catch {
            Send-Update -t 2 -c "general failure! uri was: $uri"
            Send-Update -t 2 -c "Body was $body"
            Send-Update -t 2 -c "Error was $_"
            if ($_.message.substring(0,1) -eq "{") {
                $errorResponse = $_ | Convertfrom-Json
                if ($errorResponse.message.contains("already exists")) {
                    Send-Update -t 0 -c "Secret: $secretID already exists."
                }
                else {
                    Send-Update -t 2 -c "Failed to clear secret: $secretID  with error: $errorResponse.message"
                    Send-Update -t 2 -c "Uri was: $uri"
                    Send-Update -t 2 -c "Body was: $body"
                    #exit
                }
            }

        
        }
    }
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
function Get-DelegateConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $delegateName
    )
    $uri = "https://app.harness.io/ng/api/download-delegates/kubernetes?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
    $body = @{
        "name" = $delegateName
        "tags" = @(
            $delegateName.substring(0,3)
        )
    } | ConvertTo-Json
    do {
        try {
            $response = Invoke-RestMethod -Method 'POST' -ContentType 'application/json' -uri $uri -Headers $HarnessHeaders -body $body
        }
        catch {
            $errorResponse = $_ | Convertfrom-Json
            if ($errorResponse.message.contains("Delegate with same name exists.")) {
                Send-Update -t 1 -c "$delegateName exists but is not connected. Attempting a blind delete due to yet another Harness API defect."
                $deleteUri = "https://app.harness.io/ng/api/delegate-setup/delegate/$("_$delegateName")?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
                #this worked once: 'https://app.harness.io/ng/api/delegate-setup/delegate/_gcp_delegate_event_nationwide?accountIdentifier=4jTfP5f9QNWImqbtdGEG1g&orgIdentifier=event_nationwide&projectIdentifier=string'
                Invoke-RestMethod -Method 'DEL' -uri $deleteUri -Headers $HarnessHeaders -body $body
            }
            else {
                Send-Update -t -2 -c "uri attempted was: $uri"
                Send-Update -t -2 -c "body was: $body"
                Send-Update -t 2 -c "Failed to create organization with error: $errorResponse"
                exit
            }
        }
    } until ($response)
    $response | Out-File -FilePath "$delegateName.yaml" -Force
    Send-Update -t 1 -c "Downloaded $delegateName to $delegateName.yaml"
}
function Get-DelegateStatus {
    [CmdletBinding()]
    $uri = "https://app.harness.io/ng/api/delegate-setup/listDelegates?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)&all=true"
    $body = @{
        "status"     = "CONNECTED"
        "filterType" = "Delegate"
    } | Convertto-Json
    $response = Invoke-RestMethod -method 'POST' -uri $uri -headers $HarnessHeaders -body $body -ContentType 'application/json'
    if ($response.resource) {
        return $response.resource
    }
    return $false
}
function Get-FeatureFlagStatus {
    $uri = "https://harness0.harness.io/cf/admin/features?accountIdentifier=l7B_kbSEQD2wjrM7PShm5w&projectIdentifier=FFOperations&orgIdentifier=PROD&environmentIdentifier=$($config.HarnessEnv)&targetIdentifierFilter=$($config.HarnessAccountId)&pageSize=10000"
    $response = Invoke-RestMethod -Uri $uri -method 'GET' -Headers $HarnessFFHeaders
    # parse this ridiculous API output for the values relevant to this account
    $currentFlags = [pscustomobject]@{}
    foreach ($item in $response.features) {
        $value = $item.envProperties.variationMap | Where-Object { $_.targets.identifier -eq $($config.HarnessAccountId) } | select-object -expandproperty variation
        $currentFlags | Add-Member -MemberType NoteProperty -name $item.identifier -value $value -Force
    }
    return $currentFlags
}
function Get-Filters {
    # currently unused because you have to 
    $uri = "https://app.harness.io/ccm/api/filters?pageIndex=0&pageSize=100&accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)&type=Connector"
    Invoke-RestMethod -uri $uri -headers $HarnessHeaders -method 'GET'
}
function Get-HarnessUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $email
    )
    $uri = "https://app.harness.io/ng/api/user/batch?accountIdentifier=$($config.HarnessAccountId)"
    $response = invoke-restmethod -uri $uri -headers $HarnessHeaders -ContentType "application/json" -Method 'POST'
    
    $userExists = $response.data.content | Where-Object { $_.email.Contains($email) }
    if ($userExists) { return $userExists } else { return $false }
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
function Get-PendingUser {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $email
    )
    $uri = "https://app.harness.io/ng/api/invites/aggregate?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
    $response = invoke-restmethod -uri $uri -headers $HarnessHeaders -ContentType "application/json" -Method 'POST'
    $userExists = $response.data.content | Where-Object { $_.email.Contains($email) }
    if ($userExists) { return $userExists } else { return $false }

}
function Get-Projects {
    # Get a list of projects from Harness
    $uri = "https://app.harness.io/v1/orgs/$($config.HarnessOrg)/projects&limit=50&sort=name&order=ASC"
    $response = Invoke-RestMethod -method 'GET' -uri $uri -headers $HarnessHeaders
    return $response
}
function Get-Roleassignments {
    $uri = "https://app.harness.io/authz/api/roleassignments?pageIndex=0&pageSize=50&sortOrders=fieldName%3Dstring%26orderType%3DASC&pageToken=string&accountIdentifier=$($config.HarnessAccountId)&orgidentifer=$($config.HarnessOrg)&projectidentifier=skinnyvegetable"
    Invoke-RestMethod -Method 'GET' -uri $uri -headers $HarnessHeaders
}
function Remove-Delegate {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $delegateId
    )
    $uri = "https://app.harness.io/ng/api/delegate-setup/delegate/$($delegateId)?accountIdentifier=$($config.HarnessAccountId)&orgIdentifier=$($config.HarnessOrg)"
    Invoke-RestMethod -method 'DEL' -uri $uri -headers $HarnessHeaders -ContentType 'application/json'
}
function Remove-HarnessEventDetails {
    # Set Harness flags to post-event state
    if ($config.HarnessAccount -eq "HarnessEvents") {
        Send-Update -t 1 -c "Skipping flag 'after event' state since this is the common account"
    }
    else {
        $featureFlagsStart = Get-Content -path ./harnesseventsdata/config/featureflagsend.json | Convertfrom-Json
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
    }
    # Remove event users from Harness Account
    $userdetailsuri = "https://app.harness.io/ng/api/user/batch?accountIdentifier=$($config.HarnessAccountId)&org=$($config.HarnessOrg)"
    $response = invoke-restmethod -uri $userdetailsuri -headers $HarnessHeaders -ContentType "application/json" -Method 'POST'
    $harnessUsers = $response.data.content | Where-Object { $_.email.Contains("@harnessevents.io") }
    $eventUsers = (Get-GroupMembers -s).members
    foreach ($user in $harnessUsers) {
        if ($eventUsers.email -contains $user.email) {
            $killuseruri = "https://app.harness.io/ng/api/user/$($user.uuid)?accountIdentifier=$($config.HarnessAccountId)"
            invoke-restmethod -uri $killuseruri -headers $HarnessHeaders -ContentType "application/json" -Method 'DEL' | Out-Null
            Send-Update -t 1 -c "Removed $($user.email) from account $($config.HarnessAccount)"
        }
    }
    # Wait for users to be removed
    # TODO confirm this is no longer needed - temporarily removing because we changed the logic above
    # in case this is a common account, we can't delete all harness accounts
    # $counter = 0
    # Do {
    #     $counter++
    #     if ($counter -ge 10) {
    #         Send-Update -t 2 -c "It took to long for users to be removed."
    #         exit
    #     }
    #     $response = invoke-restmethod -uri $userdetailsuri -headers $HarnessHeaders -ContentType "application/json" -Method 'POST'
    #     $eventUsers = $response.data.content | Where-Object { $_.name.Contains("@harnessevents.io") }
    #     Send-Update -t 1 -c "Waiting for $($eventUsers.count) users to be removed..."
    #     Start-Sleep -s 2
    # } until ($eventUsers.count -eq 0)
    Clear-orgSecrets
    # This worked- remove cached details for event
    return $true
}
function Remove-HarnessEventDetailsV2 {
    [CmdletBinding()]
    param (
        [Parameter()]
        [object]
        $accounts #account, org, id, pat
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
    }
    $userdetailsuri = "https://app.harness.io/ng/api/user/batch?accountIdentifier=$($account.id)&org=$($account.org)"
    $response = invoke-restmethod -uri $userdetailsuri -headers $HarnessHeaders -ContentType "application/json" -Method 'POST' -body $body
    $harnessUsers = $response.data.content | Where-Object { $_.email.Contains("@harnessevents.io") }
    #$eventUsers = (Get-GroupMembers -s).members
    foreach ($user in $harnessUsers) {
        #if ($eventUsers.email -contains $user.email) {
        $killuseruri = "https://app.harness.io/ng/api/user/$($user.uuid)?accountIdentifier=$($config.HarnessAccountId)"
        # invoke-restmethod -uri $killuseruri -headers $HarnessHeaders -ContentType "application/json" -Method 'DEL' | Out-Null
        Send-Update -t 1 -c "Removed $($user.email) from account $($config.HarnessAccount)"
        #}
    }
    if ($account.org -eq "HarnessEvents") {
        # Do specific things for HarnessEvents
        Send-Update -t 1 -c "Skipping flag 'after event' state since this is the common account"

    }
    else {
        $featureFlagsStart = Get-ChildItem -path ./harnesseventsdata/config/featureflagsend.json | Convertfrom-Json
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
    }
}
function Remove-Organization {
    # !!! This is only used in shared environments or when testing !!!
    # Ideally, attendee access will be removed and secrets cleared to provide easy onboarding later
    $uri = "https://app.harness.io/ng/api/organizations/$($config.HarnessOrg)?accountIdentifier=$($config.HarnessAccountId)"
    Send-Update -t 1 -c "Deleting harness org uri: $uri"
    Invoke-RestMethod -Method 'DEL' -headers $HarnessHeaders -uri $uri | Out-Null
    Send-update -t 1 -c "Removed the $($config.HarnessOrg) organization."
}
function Remove-PendingUser {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $inviteId
    )
    $uri = "https://app.harness.io/ng/api/invites/$($inviteId)?accountIdentifier=$($config.HarnessAccountId)"
    Send-Update -t 0 -c "Removing pending invite with uri: $uri"
    Invoke-RestMethod -Method 'DEL' -uri $uri -headers $HarnessHeaders -ContentType "application/json" | out-null

}
function Save-HarnessConfig {
    if ($config.HarnessList) {
        Send-Update -t 0 -c "Using existing history. length is: $($oldHistory.count)"
        $oldHistory = $config.HarnessList | Sort-object -property option
        $oldHistory
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
            $newHistory += [PSCustomObject]@{
                "option"           = $counter
                "HarnessAccount"   = $item.HarnessAccount
                "HarnessAccountId" = $item.HarnessAccountId
                "HarnessPAT"       = $item.HarnessPAT 
            }
            Send-Update -t 0 -c "$counter : $($item.HarnessAcount)"
            $counter++
        }
        
    }
    Set-Prefs -k "HarnessList" -v $newHistory
}
function Set-HarnessConfiguration {
    while (-not $goodToken) {
        #Show list of cached tokens
        $accountOptions = $config.HarnessList ?? @()
        $accountOptions += [PSCustomObject]@{"option" = "a";"HarnessAccount" = "<add a new harness account admin token>" }
        $accountOptions += [PSCustomObject]@{"option" = "c";"HarnessAccount" = "<use harnessevents community account>" }        
        $accountOptions | Format-Table -Property option, HarnessAccount, HarnessAccountId
        $accountChoice = Read-Host "Which account to use for the event <enter> to abort"
        if (-not $accountChoice) {
            return
        }
        if ($accountChoice.tolower() -eq "a") {
            # Offer option to add new token
            $newToken = Read-Host -prompt "Please enter a Harness *Account admin* token or <enter> to abort"
        }
        elseif ($accountChoice.tolower() -eq "c") {
            $newToken = $config.HarnessEventsPAT
        }
        else {
            # Or use a locally cached token
            $newToken = $config.HarnessList | Where-Object { $_.option -eq $accountChoice } | select-object -expandproperty HarnessPAT
        }
        if (!$newToken) {
            write-host -ForegroundColor red "`r`nHey there, could you try picking a valid option?"
            return
        }
        $checkToken = $newToken.split(".")
        # Check token for valid format
        if ($checkToken[0] -eq "pat" -and $checkToken.length -eq 4) {
            Send-Update -t 1 -c "Valid token format. Checking connectivity..."
            $response = Test-Connectivity -harnessToken $newToken
            if ($response) {
                $goodToken = $newToken
            }
            else {
                Send-Update -t 2 -c "That token looked valid, but was rejected by the API. Please retry."
            }
        }
        else {
            Send-Update -t 2 -c "Bruh, token should start with 'pat' and have 4 sections separated by periods.  Please retry."
        }
    }
    Save-HarnessConfig
    Get-Events
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

    Set-Prefs -k "HarnessAccount" -v $response.data.companyName
    Set-Prefs -k "HarnessAccountId" -v $harnessAccount
    Set-Prefs -k "HarnessPAT" -v $harnessToken
    #$choices | where-object { $_.key -eq "HARNESSCFG" } | ForEach-Object { $_.current = $config.HarnessAccount }
    # OMG Why do 2 API's use DIFFERENT strings to describe the SAME ENVIRONMENT *internal sobbing*
    $fixGodDamnEnv = $response.data.cluster.replace("-","")
    $correctEnv = $fixGodDamnEnv.substring(0,1).toUpper() + $fixGodDamnEnv.substring(1)
    if ($correctEnv -ne "Prod1") {
        Send-Update -t 2 "$correctEnv isn't the expected environment of Prod1 - just FYI if something doesn't work right."
    }
    Set-Prefs -k "HarnessEnv" -v $correctEnv
    return $response
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
    Invoke-RestMethod -Method 'Patch' -ContentType "application/json" -uri $uri -Headers $HarnessFFHeaders -body $body | Out-Null
    Send-Update -t 1 -c "feature flag $flag variation set: $value"
}

# Classroom Functions
function Get-GCP-ProjectList {
    # Retrieve administration organization
    $adminOrg = invoke-expression -Command "gcloud organizations list --filter='display_name:harnessevents.io' --format=json" | Convertfrom-Json
    $adminOrgId = $adminOrg.name.split("/")[1]
    Set-Prefs -k "AdminOrgId" -v $adminOrgId
    # Retrieve all child projects except administration
    $projects = Send-Update -t 1 -c "Retrieving projects" -r "gcloud projects list --filter='parent.id:$($config.AdminOrgId) AND -name:administration' --format=json" | Convertfrom-Json
    return $projects
}
function New-AWSProject {
    ##TODO AWS Project Functions
    Send-Update -t 1 -c "Sorry, this is not built yet!"
}
function New-AZResourceGroup {
    ##TODO Azure Resource Group Functions
    Send-Update -t 1 -c "Sorry, this is not built yet!"
}
function New-GCP-Project {
    if ($googleCloudProjectOverride) {
        Set-Prefs -k "GoogleProjectId" -v $googleCloudProjectOverride
        Set-Prefs -k "GoogleProject" -v "Command Line Override"
        Set-Prefs -k "GoogleRegion" -v "us-central1"
        $projectCheck = Send-Update -t 1 -c "Check Project Override availability" -r "gcloud projects list --filter='id:$($config.GoogleProjectId)' --format=json" | convertfrom-json
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
        # Create worker, get keys, add to IAM
        #Send-Update -t 1 -o -c "Create service account" -r "gcloud iam service-accounts create worker1"
        #Send-Update -t 1 -o -c "Grant service account permissions" -r "gcloud iam service-accounts add-iam-policy-binding worker1@$($config.GoogleProjectId).iam.gserviceaccount.com --member=serviceAccount:worker1@$($config.GoogleProjectId).iam.gserviceaccount.com --role='roles/editor'"
        #Send-Update -t 1 -o -c "Generate local key json file" -r "gcloud iam service-accounts keys create worker1.json --iam-account=worker1@$($config.GoogleProjectId).iam.gserviceaccount.com"
        # Enable API's needed for workshops
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
    }
    New-GCP-Resources
}
function New-GCP-Resources {
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
function Remove-GCP-Project {
    # Check if project exists still
    if (-not $config.GoogleProject) {
        Send-Update -t 0 -c "No Google project name found. Skipping Delete."
        return
    }
    $projectCheck = Send-Update -t 1 -c "Check for existing project" -r "gcloud projects list --filter='name:$($config.GoogleProject)' --format=json" | convertfrom-json
    if (-not $projectCheck) {
        Send-Update -t 1 -c "Project already deleted"
        Set-Prefs -k "GoogleProject"
        Set-Prefs -k "GoogleProjectId"
        return
    }
    if ($config.GoogleProjectId) {
        Send-Update -t 1 -o -c "Removing Google Project" -r "gcloud projects delete $($config.GoogleProjectId) --quiet"
        $Counter = 0
        Do {
            $counter++
            if ($counter -ge 10) {
                Send-Update -t 2 -c "Wow, something went terrrrrrribly wrong trying to remove Google Project: $($config.GoogleProjectId)"
                exit
            }
            $projectCheck = Send-Update -t 1 -c "Waiting for project delete confirmation..." -r "gcloud projects list --filter='name:$($config.GoogleProject)' --format=json" | convertfrom-json
            Start-Sleep -s 5
        } while ($projectCheck)
        Send-Update -t 1 -c "Google Project successfully removed"
        Set-Prefs -k "GoogleProjectId"
        Set-Prefs -k "GoogleProject"
    }
    else {
        Send-Update -t 1 -c "Tried removing Google Project- but no Google Project ID found in config"
    }
}
function Remove-GCPProjectV2 {
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
function Set-AWS-Project {
    #Toggle AWS Project
    SEnd-Update -t 1 -c "AWS isn't available yet"
}
function Set-Azure-Project {
    #Toggle Azure Project
    SEnd-Update -t 1 -c "Azure isn't available yet"
}
function Set-GCP-Project {
    #Toggle GCP Project
    if ($config.UseGoogleClassroom) {
        Set-Prefs -k "UseGoogleClassroom"
    }
    else {
        Set-Prefs -k "UseGoogleClassroom" -v "ENABLED"
    }
}

#Main
Test-PreFlight
Get-Prefs($Myinvocation.MyCommand.Source)
# Automated options
Get-HeadlessMode
Get-RemoveAuto
Get-JanitorMode
# Normal, looped operation for general use
Get-GoogleLogin
while ($true) {
    # Offer Options to configure event
    Add-Choice -k "EVENT" -d "Create/Switch Event" -c $config.GoogleEventName -f "Set-Event" -todo
    Add-Choice -k "HARNESSCFG" -d "Add/Switch Harness Account" -c $config.HarnessAccount -f "Set-HarnessConfiguration" -t
    Add-Choice -k "GCPCONFIG" -d "Enable/Disable GCP classroom" -c $config.UseGoogleClassroom -f "Set-GCP-Project"
    Add-Choice -k "AZURECONFIG" -d "Enable/Disable Azure classroom" -c $config.UseAwsClassroom -f "Set-Azure-Project"
    Add-Choice -k "AWSCONFIG" -d "Enable/Disable AWS classroom" -c $config.UseAzureClassroom -f "Set-AWS-Project"
    Add-Choice -k "ADDUSERS" -d "Add event attendees" -c $config.UserEventCount -f "Set-EventUsers" -t
    # Take action based on choices
    Add-Choice -k "GETDETAILS" -d "Sync/Update all event details" -f "Sync-Event"
    Add-Choice -k "DELEVENT" -d "Delete event & all classrooms" -f "Remove-Event"
    Get-Choice
}