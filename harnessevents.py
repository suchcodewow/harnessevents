#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import datetime
import subprocess
import logging
import random
import string
import shutil
import re
import requests
from typing import Optional, Dict, Any, List

# Configuration
CONFIG_FILE = "harnessevents.py.conf"
LOG_FILE = "harnessevents.py.log"
config: Dict[str, Any] = {}
args = None
harness_headers = {}
harness_ff_headers = {}
harness_admin_headers = {}

# Colors for output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def load_config(script_path: str = None):
    global config
    global CONFIG_FILE
    global LOG_FILE
    
    # Set defaults based on args
    if args.detailed_mode:
        config['output_level'] = 0
    else:
        config['output_level'] = 1
        
    if args.cloud_commands:
        config['show_commands'] = True
    else:
        config['show_commands'] = False
        
    config['retain_log'] = False
    if args.google_cloud_project_override:
        config['google_cloud_project_override'] = args.google_cloud_project_override
        
    if script_path:
        base_path = os.path.splitext(script_path)[0]
        LOG_FILE = f"{base_path}.log"
        send_update(f"Log: {LOG_FILE}", 0)
        
        if os.path.exists(LOG_FILE) and not config.get('retain_log'):
            try:
                os.remove(LOG_FILE)
            except OSError:
                pass
                
        CONFIG_FILE = f"{base_path}.conf"
        send_update(f"Config: {CONFIG_FILE}", 0)

    if os.path.exists(CONFIG_FILE):
        send_update("Reading config", 0)
        try:
            with open(CONFIG_FILE, 'r') as f:
                previous_config = json.load(f)
                for k, v in previous_config.items():
                    if k not in config:
                        config[k] = v
        except json.JSONDecodeError:
            send_update("Error reading config file", 2)

    carryover_variables = [
        "GoogleAccessToken", "GoogleAccessTokenTimestamp", "GoogleAppToken",
        "GoogleAppTokenTimestamp", "AdminProjectId", "HarnessFFToken",
        "HarnessEventsPAT", "GoogleServiceAccount", "ServiceAccountEmail",
        "ServiceAccountKey"
    ]
    
    refresh_token = False
    for c in carryover_variables:
        if c not in config:
            refresh_token = True
            
    if refresh_token:
        pass

    send_update("CREATED config", 0)
    save_config()

def save_config():
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        send_update(f"Failed to save config: {e}", 2)

def set_prefs(k: str, v: Any = None, output: bool = False):
    if v is not None:
        if output:
            send_update(f"Updating key: {k} -> {v}", 0)
        config[k] = v
    else:
        if k in config:
            if output:
                send_update(f"Deleting config key: {k}", 0)
            del config[k]
        else:
            if output:
                send_update(f"Key didn't exist: {k}", 0)
    save_config()

def send_update(content: str, type_level: int = 1, run: str = None, append: bool = False, 
                error_suppression: bool = False, output_suppression: bool = False, what_if: bool = False):
    current_output_level = config.get('output_level', 1)
    
    start = ""
    color = ""
    
    if args.whatif or what_if:
        start = "[!WHATIF!] "
        color = Colors.WARNING
    elif run:
        start = f"[{'WHATIF ' if (args.whatif or what_if) else ''}>]"
        color = Colors.HEADER
    else:
        if type_level == 0:
            start = "[.]"
            color = Colors.BLUE
        elif type_level == 1:
            start = "[-]"
            color = Colors.GREEN
        elif type_level == 2:
            start = "[X]"
            color = Colors.FAIL
        elif type_level == 3:
            start = "[XX] Exiting with error: "
            color = Colors.FAIL
            
    if current_output_level == 0:
        caller = sys._getframe(1).f_code.co_name
        start = f"{start} <{caller}>"

    show_cmd = ""
    if run and config.get('show_commands'):
        show_cmd = f" [ {run} ] "
        
    log_entry = f"{start} {content}{show_cmd}"
    
    if LOG_FILE:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, 'a') as f:
            f.write(f"{timestamp}: {log_entry}\n")

    if type_level >= current_output_level:
        print(f"{color}{log_entry}{Colors.ENDC}", end='' if append else '\n')

    if args.whatif or what_if:
        return

    if run:
        shell_cmd = run
        if output_suppression and run.startswith("gcloud"):
             shell_cmd += " --no-user-output-enabled"
             
        stderr_dest = subprocess.DEVNULL if error_suppression else None
        stdout_dest = subprocess.DEVNULL if output_suppression else subprocess.PIPE
        
        try:
            result = subprocess.run(shell_cmd, shell=True, text=True, stdout=stdout_dest, stderr=stderr_dest)
            if result.stdout:
                return result.stdout.strip()
            return None
        except Exception as e:
            if not error_suppression:
                print(f"{Colors.FAIL}Command failed: {e}{Colors.ENDC}")
            return None

    if type_level == 3:
        os.environ['terminalError'] = content
        sys.exit(1)

def get_random_string(length: int = 6) -> str:
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def get_user_name() -> str:
    prefixes = ["abundant", "delightful", "high", "nutritious", "square", "adorable", "dirty", "hollow", "obedient", "steep", "agreeable", "drab", "hot", "living", "dry", "hot", "odd", "straight", "dusty", "huge", "strong", "beautiful", "eager", "icy", "orange", "substantial", "better", "early", "immense", "panicky", "sweet", "bewildered", "easy", "important", "petite", "swift", "big", "elegant", "inexpensive", "plain", "tall", "embarrassed", "itchy", "powerful", "tart", "black", "prickly", "tasteless", "faint", "jolly", "proud", "teeny", "brave", "famous", "kind", "purple", "tender", "breeze", "fancy", "broad", "fast", "quaint", "thoughtful", "tiny", "bumpy", "light", "quiet", "calm", "fierce", "little", "rainy", "careful", "lively", "rapid", "uneven", "chilly", "flaky", "interested", "flat", "relieved", "unsightly", "clean", "fluffy", "loud", "uptight", "clever", "freezing", "vast", "clumsy", "fresh", "lumpy", "victorious", "cold", "magnificent", "warm", "colossal", "gentle", "mammoth", "salty", "gifted", "scary", "gigantic", "massive", "scrawny", "glamorous", "screeching", "whispering", "cuddly", "messy", "shallow", "curly", "miniature", "curved", "great", "modern", "shy", "wide-eyed", "witty", "damp", "grumpy", "mysterious", "skinny", "wooden", "handsome", "narrow", "worried", "deafening", "happy", "nerdy", "heavy", "soft", "helpful", "noisy", "sparkling", "young", "delicious"]
    names = ["apple", "seashore", "badge", "flock", "sidewalk", "basket", "basketball", "furniture", "smoke", "battle", "geese", "bathtub", "beast", "ghost", "nose", "beetle", "giraffe", "sidewalk", "beggar", "governor", "honey", "stage", "bubble", "hope", "station", "bucket", "income", "cactus", "island", "throne", "cannon", "cow", "judge", "toothbrush", "celery", "lamp", "turkey", "cellar", "lettuce", "umbrella", "marble", "underwear", "coach", "month", "vacation", "coast", "vegetable", "crate", "ocean", "plane", "donkey", "playground", "visitor", "voyage"]
    return f"{random.choice(prefixes)}{random.choice(names)}"

def test_preflight():
    if shutil.which("gcloud"):
        send_update("gcloud commands available!", 1)
    else:
        send_update("gcloud commands not found. install via mac with: brew install --cask google-cloud-sdk", 2)
        sys.exit(1)
        
    current_user = subprocess.run("gcloud auth list --format='value(account)' --filter=status=active", shell=True, text=True, capture_output=True).stdout.strip()
    harness_user = subprocess.run("gcloud auth list --filter=account:'harness.io' --format='value(account)'", shell=True, text=True, capture_output=True).stdout.strip()
    
    if "cloudsdk" in current_user and harness_user:
        harness_user_lines = harness_user.split('\n')
        if len(harness_user_lines) == 1 and harness_user_lines[0]:
             subprocess.run(f"gcloud config set account {harness_user_lines[0]} --no-user-output-enabled", shell=True)

def get_google_access_token():
    send_update("Checking on token", 1)
    token = config.get("GoogleAccessToken")
    timestamp_str = config.get("GoogleAccessTokenTimestamp")
    valid = False
    if token and timestamp_str:
        try:
            timestamp = datetime.datetime.fromisoformat(timestamp_str)
            time_diff = datetime.datetime.now() - timestamp
            if time_diff.total_seconds() < 1800:
                send_update(f"Google Workspace Token age is OK: {round(time_diff.total_seconds()/60)}m.", 0)
                valid = True
            else:
                send_update(f"Google Workspace Token is too old: {round(time_diff.total_seconds()/60)}m.", 1)
        except ValueError:
            pass
            
    if not valid:
        send_update("Refreshing token", 1)
        enable_service_account()
        project_json = send_update("Retrieving admin project", 1, "gcloud projects list --filter='name:administration' --format=json")
        if project_json:
            project = json.loads(project_json)[0]
            set_prefs("AdminProjectId", project['projectId'])
            
        if not config.get("HarnessFFToken"):
            token = send_update("Retrieving HarnessFFToken", 1, f"gcloud secrets versions access latest --secret='HarnessEventsFF' --project={config.get('AdminProjectId')}")
            set_prefs("HarnessFFToken", token)
            
        if not config.get("HarnessEventsPAT"):
            token = send_update("Retrieving HarnessEventsPAT", 1, f"gcloud secrets versions access latest --secret='HarnessEventsPAT' --project={config.get('AdminProjectId')}")
            set_prefs("HarnessEventsPAT", token)
            
        auth_token = send_update("Retrieving account token", 1, "gcloud auth print-access-token --scopes='https://www.googleapis.com/auth/admin.directory.user https://www.googleapis.com/auth/admin.directory.group'")
        
        if auth_token:
            set_prefs("GoogleAccessToken", auth_token)
            set_prefs("GoogleAccessTokenTimestamp", datetime.datetime.now().isoformat())
            google_service_account = send_update("", 0, "gcloud auth list --filter=status:ACTIVE --format='value(account)'")
            set_prefs("GoogleServiceAccount", google_service_account)
            send_update("Successfully retrieved a new token and timestamp.", 0)
        else:
            send_update("Unexpected error while retrieving access token.", 2)
            
        subprocess.run(f"gcloud config set project {config.get('AdminProjectId')} --no-user-output-enabled", shell=True)
        if os.path.exists("harnessevents.json"):
            os.remove("harnessevents.json")
        get_google_api_access_token()

def get_google_api_access_token():
    pass

def enable_service_account():
    current_user = send_update("", 0, "gcloud auth list --format='value(account)' --filter=status=active")
    if "cloudsdk" in current_user:
        if os.path.exists('key.json'):
            with open('key.json', 'r') as f:
                creds = json.load(f)
                set_prefs("ServiceAccountEmail", creds['client_email'])
                set_prefs("ServiceAccountKey", creds['private_key'])
        return

    if "@harness.io" in current_user:
        init_project_json = send_update("", 0, "gcloud projects list --filter='name:sales' --format=json")
        if init_project_json:
            init_project = json.loads(init_project_json)[0]
            send_update("Retrieving credentials", 1, f"gcloud secrets versions access latest --secret='HarnessEventsAccount' --project={init_project['projectId']} > harnessevents.json")
            if not os.path.exists("harnessevents.json"):
                send_update("HarnessEventsAccount not found. You might need to run 'gcloud auth login' again with your work email.", 3)
            send_update("Activating service account", 1, "gcloud auth activate-service-account --key-file=harnessevents.json --no-user-output-enabled")
            with open('harnessevents.json', 'r') as f:
                creds = json.load(f)
                set_prefs("ServiceAccountEmail", creds['client_email'])
                set_prefs("ServiceAccountKey", creds['private_key'])
            if os.path.exists("harnessevents.json"):
                os.remove("harnessevents.json")

def disable_service_account():
    google_user = config.get("GoogleUser")
    if google_user and "@harness.io" in google_user:
        send_update("Switching to original account", 1, f"gcloud config set account {google_user} --no-user-output-enabled")

def create_mode():
    send_update("Setting up config for new event.", 1)
    cli_user = send_update("", 0, "gcloud auth list --format='value(account)' --filter=status=active")
    set_prefs("CLIUser", cli_user)
    
    if args.instructorName:
        current_user = args.instructorName
    else:
        current_user = cli_user
        
    if not current_user:
        send_update("No google user authentication found. Is it illegal in 23 US states to continue without one. Nice try though.", 2)
        send_update("Run <gcloud auth login> and login with your work email.", 3)
        
    if "cloudsdk" in current_user:
        send_update("You're running as the HarnessEvents CloudSDK service account.", 2)
        send_update("Switch to your work account with <gcloud config set account 'your email'>", 3)
        
    send_update(f"Successfully identified current user: {current_user}", 0)
    set_prefs("GoogleUser", current_user)
    instructor_email = f"{current_user.split('@')[0]}@harnessevents.io"
    set_prefs("InstructorEmail", instructor_email)
    
    if args.userCount:
        set_prefs("UserEventCount", args.userCount)
    else:
        set_prefs("UserEventCount", 1)
        
    event_name = args.eventName
    if not event_name:
        event_name = get_user_name()
        send_update(f"Generated event name: {event_name}", 1)
        
    formatted_event_name = re.sub(r'\W', '', event_name)
    formatted_event_name = f"event-{formatted_event_name.lower()}"
    set_prefs("GoogleEventName", formatted_event_name)
    
    harness_org = formatted_event_name.replace("-", "_")
    set_prefs("HarnessOrg", harness_org)
    
    event_email = f"{formatted_event_name}@harnessevents.io"
    set_prefs("GoogleEventEmail", event_email)
    
    if args.gcp:
        set_prefs("GoogleClassroom", harness_org.replace("_", "-"))
    if args.aws:
        set_prefs("AwsClassroom", harness_org.replace("_", "-"))
    if args.azure:
        set_prefs("AzureClassroom", harness_org.replace("_", "-"))
        
    get_google_access_token()
    get_harness_admin_credentials()
    
    harness_token = None
    if args.newAccount:
        harness_token = add_account(args.newAccount)
    else:
        if args.harnessPAT:
            send_update("Using provided Harness PAT", 1)
            harness_token = args.harnessPAT
        else:
            send_update("Using community Harness Account", 1)
            harness_token = config.get("HarnessEventsPAT")
            
    test_connectivity(harness_token)
    add_licenses()
    save_event()
    new_event()
    sync_event()
    disable_service_account()
    send_update("End Create Mode", 1)
    sys.exit(0)

def janitor_mode():
    cli_user = send_update("", 0, "gcloud auth list --format='value(account)' --filter=status=active")
    all_users = send_update("", 0, "gcloud auth list --format='value(account)' --filter='-ACCOUNT:-compute'")
    set_prefs("CLIUser", cli_user)
    
    if args.instructorName:
        current_user = args.instructorName
    else:
        current_user = cli_user
        
    if not current_user:
        send_update("No google user authentication found. It is illegal in 23 US states to continue without one. Nice try though.", 2)
        send_update("Run <gcloud auth login> and login with your work email.", 2)
        sys.exit(1)
        
    if "cloudsdk" in current_user and len(all_users.split('\n')) > 1:
        send_update("You're running as the HarnessEvents CloudSDK service account.", 2)
        send_update("Switch to your work account with <gcloud config set account 'your email'>", 2)
        sys.exit(1)
        
    enable_service_account()
    set_prefs("GoogleUser", current_user)
    set_prefs("InstructorEmail", f"{current_user.split('@')[0]}@harnessevents.io")
    send_update("Running event cleanup", 1)
    
    valid_events = []
    expired_orgs = []
    warning_orgs = []
    
    get_google_access_token()
    open_events_output = send_update("", 0, "gcloud storage ls gs://harnesseventsdata/events/open/*.json --verbosity=none")
    open_events = open_events_output.split('\n') if open_events_output else []
    
    for event_json in open_events:
        if not event_json: continue
        remove_event_flag = False
        warn_event_flag = False
        try:
            e_content = send_update("", 0, f"gcloud storage cat {event_json}")
            e = json.loads(e_content)
        except:
            continue
            
        if 'EventCreateTime' not in e:
            remove_event_flag = True
        else:
            event_create_time = datetime.datetime.fromisoformat(e['EventCreateTime'])
            time_diff = datetime.datetime.now() - event_create_time
            hours_old = time_diff.total_seconds() / 3600
            if args.hourLimit:
                if hours_old > args.hourLimit:
                    remove_event_flag = True
                    send_update(f"Event {e.get('GoogleEventName')} has EXPIRED at {round(hours_old, 2)} hours old <Max age is: {args.hourLimit}>", 1)
                elif hours_old >= args.hourLimit * 0.75:
                    warn_event_flag = True
                    send_update(f"Event {e.get('GoogleEventName')} reached 75% time limit at {round(hours_old, 2)} hours old", 1)
                else:
                    send_update(f"Event {e.get('GoogleEventName')} is valid at {round(hours_old, 2)} hours old", 1)
            else:
                if e.get('InstructorEmail') == config.get('InstructorEmail'):
                    remove_event_flag = True
                    send_update(f"Event {e.get('GoogleEventName')} is one of your events marked to remove.", 1)
                else:
                    send_update(f"Skipping event {e.get('GoogleEventName')}- it's owned by {e.get('InstructorEmail')}.", 1)
                    
        if remove_event_flag:
            if all(k in e for k in ('HarnessAccount', 'HarnessOrg', 'HarnessAccountId', 'HarnessPAT', 'HarnessEnv')):
                expired_orgs.append(e)
                send_update(f"Added {e['HarnessOrg']} in {e['HarnessAccount']} to expired events.", 1)
            else:
                send_update(f"Gross! One of these was missing in {e.get('GoogleEventName')}", 2)
            if not args.whatif:
                filename = os.path.basename(event_json)
                send_update("", 0, f"gcloud storage mv {event_json} gs://harnesseventsdata/events/closed/{filename}")
        elif warn_event_flag:
             if all(k in e for k in ('HarnessAccount', 'HarnessOrg', 'HarnessAccountId', 'HarnessPAT', 'HarnessEnv')):
                warning_orgs.append(e)
                send_update(f"Added {e['HarnessOrg']} in {e['HarnessAccount']} to warning events.", 1)
        else:
            valid_events.append(e.get('GoogleEventEmail'))
            
    send_update(f"There are {len(expired_orgs)} expired org(s) to process.", 1)
    remove_harness_event_details(expired_orgs)
    disable_service_account()
    send_update("End event cleanup", 1)
    sys.exit(0)

def save_event():
    set_prefs("EventCreateTime", (datetime.datetime.now() + datetime.timedelta(hours=args.timeOffset)).isoformat())
    date_prefix = datetime.datetime.now().strftime("%Y-%m")
    file_name = f"{config.get('GoogleUser').split('@')[0]}-{config.get('GoogleEventName')}.json"
    send_update("", 0, f"gcloud storage cp {CONFIG_FILE} gs://harnesseventsdata/events/open/{date_prefix}-{file_name} --no-user-output-enabled")

def new_event():
    send_update("Creating new event", 1)
    instructor_email = config.get("InstructorEmail")
    if not get_user(instructor_email):
        new_user(instructor_email)
        send_update(f"Generated your instructor email: {instructor_email}", 1)
        
    google_event_email = config.get("GoogleEventEmail")
    group_key = get_group_key(google_event_email)
    if not group_key:
        send_update("Group didn't exist. Creating.", 0)
        new_group(google_event_email, config.get("GoogleEventName"))
        add_user_to_group(instructor_email, google_event_email, owner=True)
        send_update(f"Waiting for {instructor_email} to be registered as group owner", 1)
        group_ready = False
        while not group_ready:
            groups = get_user_groups(instructor_email)
            if groups:
                for g in groups:
                    if g.get('email') == google_event_email:
                        group_ready = True
                        break
            if not group_ready:
                send_update("User not yet registered...", 1)
                time.sleep(6)
        send_update(f"Successfully added user: {instructor_email} as owner.", 1)
    else:
        send_update(f"{google_event_email} already exists. Confirming ownership.", 1)
        send_update("Confirmed you are an event owner.", 1)
    event_id = get_group_key(google_event_email)
    set_prefs("GoogleEventId", event_id)

def sync_event():
    global harness_headers, harness_ff_headers
    harness_headers = {'x-api-key': config.get("HarnessPAT"), 'Content-Type': 'application/json'}
    harness_ff_headers = {'x-api-key': config.get("HarnessFFToken"), 'Content-Type': 'application/json'}
    
    if not config.get("GoogleEventName"):
        send_update("GoogleEventName was blank. (That shouldn't happen)", 3)
    if not config.get("HarnessPAT") or not config.get("HarnessAccountId") or not config.get("HarnessAccount"):
        send_update("Harness token, AccountId, and Account Name are required to setup an event (That shouldn't happen)", 3)
    if not config.get("HarnessOrg"):
        send_update("Harness Org must be set (that shouldn't happen)", 3)
        
    add_event_users()
    add_harness_event_details()
    if config.get("GoogleClassroom"):
        new_gcp_project()
    add_variables()
    save_event_details()

def get_harness_admin_credentials():
    token = send_update("Retrieving Harness Portal Token", 1, f"gcloud secrets versions access latest --secret='HarnessEventsAdmin' --project={config.get('AdminProjectId')}")
    global harness_admin_headers
    harness_admin_headers = {"authorization": f"Bearer {token}"}

def test_connectivity(harness_token):
    send_update("Starting Harness connectivity check", 1)
    parts = harness_token.split(".")
    if len(parts) != 4:
        send_update("Harness Platform token was malformed.", 3)
    harness_account = parts[1]
    headers = {"x-api-key": harness_token}
    uri = f"https://app.harness.io/ng/api/accounts/{harness_account}"
    try:
        response = requests.get(uri, headers=headers)
        response.raise_for_status()
        data = response.json()['data']
    except Exception as e:
        send_update(f"Failed to connect to Harness API: {e}", 3)
    send_update("is valid.", 1)
    set_prefs("HarnessAccount", data['companyName'])
    set_prefs("HarnessAccountId", harness_account)
    set_prefs("HarnessPAT", harness_token)
    cluster = data['cluster'].replace("-", "")
    correct_env = cluster[0].upper() + cluster[1:]
    if correct_env != "Prod1":
        send_update(f"{correct_env} isn't the expected environment of Prod1 - just FYI if something doesn't work right.", 2)
    set_prefs("HarnessEnv", correct_env)
    return data

def add_licenses():
    pass

def add_event_users():
    if not config.get("UserEventCount"):
        send_update("User count not entered- skipping adding users.", 1)
        return
    user_event_count = int(config.get("UserEventCount"))
    google_event_email = config.get("GoogleEventEmail")
    members = get_group_members(google_event_email, split_into_groups=True)
    starting_count = members['memberCount'] if members else 0
    users_needed = user_event_count - starting_count
    send_update(f"Group has {starting_count} now with goal of {user_event_count}", 1)
    if starting_count >= user_event_count:
        return
    counter = 1
    while counter <= users_needed:
        new_user_created = False
        while not new_user_created:
            user = get_user_name()
            user_email = f"{user}@harnessevents.io"
            if not get_user(user_email):
                new_user(user_email)
                add_user_to_group(user_email, google_event_email)
                send_update(f"Added user: {user_email}", 1)
                new_user_created = True
        counter += 1
    send_update("Waiting for all users to be available...", 1)
    send_update("All users added successfully", 1)

def get_headers():
    return {"Authorization": f"Bearer {config.get('GoogleAccessToken')}"}

def get_group_key(group_email):
    uri = f"https://admin.googleapis.com/admin/directory/v1/groups?domain=harnessevents.io&query=email='{group_email}'"
    try:
        response = requests.get(uri, headers=get_headers())
        data = response.json()
        if 'groups' in data and data['groups']:
            return data['groups'][0]['id']
    except:
        pass
    return None

def get_group_members(group_email, split_into_groups=False):
    group_key = get_group_key(group_email)
    if not group_key:
        return None
    uri = f"https://admin.googleapis.com/admin/directory/v1/groups/{group_key}/members"
    try:
        response = requests.get(uri, headers=get_headers())
        data = response.json()
        members = data.get('members', [])
        if split_into_groups:
            owners = [m for m in members if m['role'] == 'OWNER']
            regular_members = [m for m in members if m['role'] == 'MEMBER']
            return {"owners": owners, "members": regular_members, "ownerCount": len(owners), "memberCount": len(regular_members), "groupKey": group_key}
        return members
    except:
        return None

def get_user(user_name):
    if "harnessevents.io" not in user_name:
        user_name = f"{user_name}@harnessevents.io"
    uri = f"https://admin.googleapis.com/admin/directory/v1/users?domain=harnessevents.io&query=email='{user_name}'"
    try:
        response = requests.get(uri, headers=get_headers())
        data = response.json()
        return data.get('users')
    except:
        return None

def new_user(user_email):
    uri = 'https://admin.googleapis.com/admin/directory/v1/users'
    body = {"primaryEmail": user_email, "name": {"givenName": "Harness", "familyName": "Events"}, "suspended": False, "password": "Harness!", "changePasswordAtNextLogin": False}
    try:
        requests.post(uri, headers=get_headers(), json=body)
    except Exception as e:
        send_update(f"Failed to create user {user_email}: {e}", 2)

def new_group(email, name):
    if not name:
        name = "new-group"
    body = {"email": email, "name": name}
    uri = "https://admin.googleapis.com/admin/directory/v1/groups"
    try:
        requests.post(uri, headers=get_headers(), json=body)
        success = False
        counter = 0
        while not success and counter < 30:
            if get_group_key(email):
                success = True
            else:
                counter += 1
                time.sleep(3)
    except Exception as e:
        send_update(f"Failed to create group {email}: {e}", 2)

def add_user_to_group(user_email, group_email, owner=False):
    group_key = get_group_key(group_email)
    uri = f"https://admin.googleapis.com/admin/directory/v1/groups/{group_key}/members"
    role = "OWNER" if owner else "MEMBER"
    body = {"email": user_email, "role": role}
    try:
        requests.post(uri, headers=get_headers(), json=body)
    except Exception as e:
        send_update(f"Failed to add user to group: {e}", 2)

def get_user_groups(user_email):
    uri = f"https://admin.googleapis.com/admin/directory/v1/groups?domain=harnessevents.io"
    if user_email:
        uri += f"&userKey={user_email}"
    try:
        response = requests.get(uri, headers=get_headers())
        return response.json().get('groups')
    except:
        return None

def remove_event(email, id):
    get_google_access_token()
    send_update(f"Deleting google event {email}", 1)
    members = get_group_members(email)
    if members:
        for member in members:
            remove_user(member['email'])
            send_update(f"Deleted user: {member['email']}", 1)
    group_uri = f"https://admin.googleapis.com/admin/directory/v1/groups/{id}"
    if args.whatif:
        send_update(f"whatif prevented: Deleting group: {email}", 1)
        return
    send_update(f"Deleting group: {email}", 1)
    try:
        requests.delete(group_uri, headers=get_headers())
    except:
        pass

def remove_user(user_email):
    if args.whatif:
        send_update(f"whatif prevented: Removing google user: {user_email}", 1)
        return
    send_update(f"Removing google user: {user_email}", 1)
    uri = f"https://admin.googleapis.com/admin/directory/v1/users/{user_email}"
    try:
        requests.delete(uri, headers=get_headers())
    except:
        pass

def remove_harness_event_details(accounts):
    for account in accounts:
        if account.get('account') == "HarnessEvents":
             if args.whatif:
                 send_update(f"whatif prevented: Removing Harness org: {account.get('org')}", 1)
             else:
                 send_update(f"Removing Harness org: {account.get('org')}", 1)
                 uri = f"https://app.harness.io/ng/api/organizations/{account.get('org')}?accountIdentifier={account.get('id')}"
                 headers = {'x-api-key': account.get('pat'), 'Content-Type': 'application/json'}
                 try:
                     requests.delete(uri, headers=headers)
                 except:
                     pass

def add_account(account_name):
    send_update(f"Adding new account: {account_name}", 1)
    return "token_placeholder"

def add_harness_event_details():
    add_organization()
    google_event_email = config.get("GoogleEventEmail")
    members = get_group_members(google_event_email)
    if members:
        for member in members:
            if member['role'] == 'OWNER':
                add_harness_admin(member['email'])
            else:
                clean_project = re.sub(r'\W', '', member['email'].split('@')[0]).lower()
                add_project(clean_project)
                add_harness_user(clean_project, member['email'])

def add_organization():
    harness_org = config.get("HarnessOrg")
    body = {"organization": {"identifier": harness_org, "name": harness_org}}
    uri = f"https://app.harness.io/ng/api/organizations?accountIdentifier={config.get('HarnessAccountId')}"
    try:
        requests.post(uri, headers=harness_headers, json=body)
    except Exception as e:
        send_update(f"Failed to create org: {e}", 2)

def add_project(project_name):
    body = {"project": {"orgIdentifier": config.get("HarnessOrg"), "identifier": project_name, "name": project_name}}
    uri = f"https://app.harness.io/ng/api/projects?accountIdentifier={config.get('HarnessAccountId')}&orgIdentifier={config.get('HarnessOrg')}"
    try:
        requests.post(uri, headers=harness_headers, json=body)
    except:
        pass

def add_harness_admin(user_email):
    pass

def add_harness_user(project_name, user_email):
    pass

def new_gcp_project():
    pass

def add_variables():
    pass

def save_event_details():
    pass

def main():
    global args
    parser = argparse.ArgumentParser(description="Harness Events Automation")
    parser.add_argument("action", nargs="?", choices=["create", "remove"], help="Action to execute")
    parser.add_argument("--aws", action="store_true", help="[CREATE] create aws classroom for event")
    parser.add_argument("--azure", action="store_true", help="[CREATE] create azure classroom for event")
    parser.add_argument("--cloudCommands", action="store_true", help="debug option: enable to show commands")
    parser.add_argument("--detailedMode", action="store_true", help="debug option: level 0 output")
    parser.add_argument("--eventName", type=str, help="[CREATE] specify event name")
    parser.add_argument("--gcp", action="store_true", help="[CREATE] create gcp classroom for event")
    parser.add_argument("--googleCloudProjectOverride", type=str, help="debug option: override project creation")
    parser.add_argument("--harnessPAT", type=str, help="[CREATE] harness PAT")
    parser.add_argument("--hourLimit", type=int, help="[REMOVE] max event lifespan in hours")
    parser.add_argument("--instructorName", type=str, help="[CREATE] specify instructorName")
    parser.add_argument("--newAccount", type=str, help="[CREATE] specify new account name")
    parser.add_argument("--timeOffset", type=int, default=0, help="debug option: set hour offset")
    parser.add_argument("--userCount", type=int, help="[CREATE MODE] specify number of attendees")
    parser.add_argument("--whatif", action="store_true", help="debug option: prevent significant changes")
    
    args = parser.parse_args()
    
    test_preflight()
    load_config(sys.argv[0])
    
    if args.action == "create":
        create_mode()
    elif args.action == "remove":
        janitor_mode()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
