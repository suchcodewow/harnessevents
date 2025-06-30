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

# Google Functions
Get-ProjectList {
    
}
# Main
Get-Prefs($Myinvocation.MyCommand.Source)