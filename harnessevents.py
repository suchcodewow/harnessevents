#!/usr/bin/env python3
# This doesn't work. was a fun test to see if AI could swap script types.  It failed. It failed real, real bad.
"""
Harness Events Script - Python version
This script manages Harness events for classroom environments in GCP, AWS, and Azure.
"""
import os
import sys
import json
import time
import random
import string
import datetime
import argparse
import subprocess
import requests
from typing import Dict, Any, List, Optional, Union

# Global variables
config = {}
log_file = None
config_file = None
output_level = 1
show_commands = False
current_log_entry = None

def get_random_string(character_count: int = 6) -> str:
    """Generate a random string of characters of specified length"""
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(character_count))

def get_username() -> str:
    """Generate a fun PG-rated madlibs-style username"""
    prefixes = [
        "abundant", "delightful", "high", "nutritious", "square", "adorable",
        "dirty", "hollow", "obedient", "steep", "agreeable", "drab", "hot",
        "living", "dry", "hot", "odd", "straight", "dusty", "huge", "strong",
        "beautiful", "eager", "icy", "orange", "substantial", "better", "early",
        "immense", "panicky", "sweet", "bewildered", "easy", "important", "petite",
        "swift", "big", "elegant", "inexpensive", "plain", "tall", "embarrassed",
        "itchy", "powerful", "tart", "black", "prickly", "tasteless", "faint",
        "jolly", "proud", "teeny", "brave", "famous", "kind", "purple", "tender",
        "breeze", "fancy", "broad", "fast", "quaint", "thoughtful", "tiny", "bumpy",
        "light", "quiet", "calm", "fierce", "little", "rainy", "careful", "lively",
        "rapid", "uneven", "chilly", "flaky", "interested", "flat", "relieved",
        "unsightly", "clean", "fluffy", "loud", "uptight", "clever", "freezing",
        "vast", "clumsy", "fresh", "lumpy", "victorious", "cold", "magnificent",
        "warm", "colossal", "gentle", "mammoth", "salty", "gifted", "scary",
        "gigantic", "massive", "scrawny", "glamorous", "screeching", "whispering",
        "cuddly", "messy", "shallow", "curly", "miniature", "curved", "great",
        "modern", "shy", "wide-eyed", "witty", "damp", "grumpy", "mysterious",
        "skinny", "wooden", "handsome", "narrow", "worried", "deafening", "happy",
        "nerdy", "heavy", "soft", "helpful", "noisy", "sparkling", "young", "delicious"
    ]
    
    names = [
        "apple", "seashore", "badge", "flock", "sidewalk", "basket", "basketball",
        "furniture", "smoke", "battle", "geese", "bathtub", "beast", "ghost", "nose",
        "beetle", "giraffe", "sidewalk", "beggar", "governor", "honey", "stage",
        "bubble", "hope", "station", "bucket", "income", "cactus", "island", "throne",
        "cannon", "cow", "judge", "toothbrush", "celery", "lamp", "turkey", "cellar",
        "lettuce", "umbrella", "marble", "underwear", "coach", "month", "vacation",
        "coast", "vegetable", "crate", "ocean", "plane", "donkey", "playground", "visitor",
        "voyage"
    ]
    
    return f"{random.choice(prefixes)}{random.choice(names)}"

def set_prefs(key: str, value: str = None) -> None:
    """Set a new keypair value in the config"""
    global config
    
    if value:
        send_update(f"Updating key: {key} -> {value}", 0)
        config[key] = value
    else:
        if key and key in config:
            send_update(f"Deleting config key: {key}", 0)
            del config[key]
        else:
            send_update(f"Key didn't exist: {key}", 0)
    
    if config_file:
        with open(config_file, 'w') as f:
            json.dump(config, f)

def send_update(content: str = "", type_level: int = 0, run: str = None, append: bool = False, 
                error_suppression: bool = False, output_suppression: bool = False, what_if: bool = False) -> Any:
    """Handle output to screen & log, execute commands and return results"""
    global current_log_entry
    
    if what_if:
        what_if_comment = "!WHATIF! "
    else:
        what_if_comment = ""
    
    if run:
        color = "magenta" # Using ANSI color codes would be implementation
        start = f"[{what_if_comment}>]"
    else:
        if type_level == 0:
            color = "blue"
            start = "[.]"
        elif type_level == 1:
            color = "green"
            start = "[-]"
        elif type_level == 2:
            color = "red"
            start = "[X]"
        elif type_level == 3:
            color = "red"
            start = "[XX] Exiting with error: "
        else:
            color = "gray"
            start = ""
    
    # Add function name to debug output
    if output_level == 0:
        import inspect
        caller_frame = inspect.currentframe().f_back
        function_name = caller_frame.f_code.co_name if caller_frame else "Unknown"
        start = f"{start} <{function_name}>"
    
    # Format the command to show on screen
    show_cmd = f" [ {run} ] " if run and show_commands else ""
    
    if current_log_entry:
        screen_output = f"{content}{show_cmd}"
    else:
        screen_output = f"   {start} {content}{show_cmd}"
    
    if append:
        current_log_entry = f"{current_log_entry} {content}{show_cmd}" if current_log_entry else f"{content}{show_cmd}"
    else:
        # This is the last item in-line. Write it out if log exists
        if log_file:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(log_file, 'a') as f:
                log_content = f"{timestamp}: {current_log_entry} {content}{show_cmd}" if current_log_entry else f"{timestamp}: {content}{show_cmd}"
                f.write(log_content + "\n")
        
        # Reset inline recording
        current_log_entry = None
    
    # Output if user wants to see this level of content
    if type_level >= output_level:
        # In a real implementation, we would use colorama or another library for colors
        print(screen_output)
    
    if what_if:
        return None
    
    if run:
        # Execute the command and handle output based on flags
        if run.startswith("gcloud") and output_suppression:
            run = f"{run} --no-user-output-enabled"
        
        try:
            if error_suppression and output_suppression:
                result = subprocess.run(run, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                return result.returncode == 0
            elif error_suppression:
                result = subprocess.run(run, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                return result.stdout
            elif output_suppression:
                result = subprocess.run(run, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                return result.returncode == 0
            else:
                result = subprocess.run(run, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode != 0 and not error_suppression:
                    print(f"Error executing command: {result.stderr}")
                return result.stdout.strip()
        except Exception as e:
            if not error_suppression:
                print(f"Exception running command: {e}")
            return None
    
    # If this is a terminal error, exit
    if type_level == 3:
        os.environ['terminalError'] = content
        send_update("Error written to environment variable: terminalError", 2)
        sys.exit(1)
    
    return None

def get_prefs(script_path: str = None) -> None:
    """Initialize preferences and configuration"""
    global config, log_file, config_file, output_level, show_commands
    
    # Set defaults based on command line args
    if args.verbose_mode:
        output_level = 0
    else:
        output_level = 1
    
    if args.cloud_commands:
        show_commands = True
    else:
        show_commands = False
    
    retain_log = False
    
    if args.google_cloud_project_override:
        google_cloud_project_override = args.google_cloud_project_override
    
    if script_path:
        log_file = f"{script_path}.log"
        send_update(f"Log: {log_file}", 0)
        if os.path.exists(log_file) and not retain_log:
            os.remove(log_file)
        
        config_file = f"{script_path}.conf"
        send_update(f"Config: {config_file}", 0)
    
    choice_columns = ["Option", "description", "current", "key", "callFunction", "callProperties"] if output_level == 0 else ["Option", "description", "current"]
    provider_columns = ["option", "provider", "name", "identifier", "userid", "default"] if output_level == 0 else ["option", "provider", "name"]
    event_columns = ["option", "Name", "Email", "ID", "default"] if output_level == 0 else ["option", "Name", "Email"]
    
    # Load previous config if exists
    previous_config = {}
    if os.path.exists(config_file):
        send_update("Reading config", 0)
        with open(config_file, 'r') as f:
            try:
                previous_config = json.load(f)
            except json.JSONDecodeError:
                send_update("Error parsing config file", 2)
    
    # Initialize config
    config = {}
    with open(config_file, 'w') as f:
        json.dump(config, f)
    
    # Carry over variables from previous config
    carryover_variables = [
        "GoogleAccessToken", "GoogleAccessTokenTimestamp", "GoogleAppToken",
        "GoogleAppTokenTimestamp", "AdminProjectId", "HarnessFFToken",
        "HarnessEventsPAT", "GoogleAccessToken", "GoogleServiceAccount",
        "ServiceAccountEmail", "ServiceAccountKey"
    ]
    
    refresh_token = False
    for var in carryover_variables:
        if var in previous_config:
            set_prefs(var, previous_config[var])
        else:
            refresh_token = True
    
    # If we're missing any variables trigger a full refresh
    if refresh_token:
        set_prefs("GoogleAccessToken")
    
    send_update("CREATED config", 0)

def test_preflight() -> None:
    """Make sure required commands are available"""
    # Check if gcloud is installed
    try:
        send_update("Checking for gcloud...", 1, append=True)
        result = subprocess.run("which gcloud", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            send_update("gcloud commands available!", 1)
        else:
            send_update("gcloud commands not found. install via mac with: brew install --cask google-cloud-sdk", 2)
            sys.exit(1)
    except Exception:
        send_update("Error checking for gcloud", 2)
        sys.exit(1)
    
    # Check if using cloudsdk but there is a normal user account. Switch if so.
    try:
        current_user = send_update("", 0, "gcloud auth list --format='value(account)' --filter=status=active")
        harness_user = send_update("", 0, "gcloud auth list --filter=account:'harness.io' --format='value(account)'")
        
        if "cloudsdk" in current_user and harness_user:
            send_update("", 0, f"gcloud config set account {harness_user} --no-user-output-enabled")
    except Exception as e:
        send_update(f"Error checking gcloud auth: {e}", 2)

def get_google_access_token() -> None:
    """Get Google API access token"""
    # Check if token exists and is not expired
    if "GoogleAccessToken" in config and "GoogleAccessTokenTimestamp" in config:
        token_timestamp = datetime.datetime.fromisoformat(config["GoogleAccessTokenTimestamp"])
        time_diff = datetime.datetime.now() - token_timestamp
        
        if time_diff.total_seconds() < 3600:  # Less than 1 hour
            send_update(f"Token age is OK: {int(time_diff.total_seconds() / 60)}m", 0)
            headers = {"Authorization": f"Bearer {config['GoogleAccessToken']}"}
            return
    
    # Retrieve Google service account key file
    send_update("Retrieving service account key...", 1)
    subprocess.run("gcloud secrets versions access latest --secret='harnessevents' --project=administration > harnessevents.json", shell=True)
    
    # Get Harness FF token and HarnessEvents PAT
    if "HarnessFFToken" not in config:
        harness_ff_token = send_update("Retrieving credentials", 1, 
                                      f"gcloud secrets versions access latest --secret='HarnessEventsFF' --project={config.get('AdminProjectId', 'administration')}")
        set_prefs("HarnessFFToken", harness_ff_token)
    
    if "HarnessEventsPAT" not in config:
        harness_events_pat = send_update("Snagging HarnessEvents PAT", 1, 
                                        f"gcloud secrets versions access latest --secret='HarnessEventsPAT' --project={config.get('AdminProjectId', 'administration')}")
        set_prefs("HarnessEventsPAT", harness_events_pat)
    
    # Get authorization code
    authorization_code = send_update("Retrieving account token", 1, 
                                   "gcloud auth print-access-token --scopes='https://www.googleapis.com/auth/admin.directory.user https://www.googleapis.com/auth/admin.directory.group'")
    
    if authorization_code:
        # Save valid token
        set_prefs("GoogleAccessToken", authorization_code)
        set_prefs("GoogleAccessTokenTimestamp", datetime.datetime.now().isoformat())
        
        # Save the name of the google account to use later
        google_service_account = subprocess.run("gcloud auth list --filter=status:ACTIVE --format='value(account)'", 
                                               shell=True, stdout=subprocess.PIPE, text=True).stdout.strip()
        set_prefs("GoogleServiceAccount", google_service_account)
        
        headers = {"Authorization": f"Bearer {config['GoogleAccessToken']}"}
        send_update("Successfully retrieved a new token and timestamp.", 0)
    else:
        send_update("Unexpected error while retrieving access token.", 2)
    
    # Set project to avoid caching issues
    send_update("", 0, f"gcloud config set project {config.get('AdminProjectId', 'administration')} --no-user-output-enabled")
    
    # Parse credentials JSON
    if os.path.exists('harnessevents.json'):
        with open('harnessevents.json', 'r') as f:
            credentials_json = json.load(f)
        
        set_prefs("ServiceAccountEmail", credentials_json["client_email"])
        private_key = credentials_json["private_key"]
        private_key = private_key.replace('-----BEGIN PRIVATE KEY-----\n', '')
        private_key = private_key.replace('\n-----END PRIVATE KEY-----\n', '')
        private_key = private_key.replace('\n', '')
        set_prefs("ServiceAccountKey", private_key)
        
        # Cleanup file
        if os.path.exists('harnessevents.json'):
            os.remove('harnessevents.json')
        
        # Get API token for Google Drive and Sheets
        get_google_api_access_token()

def get_google_api_access_token() -> None:
    """Get token for Google Drive and Sheets API access"""
    # Check if token exists and is not expired
    if "GoogleAppToken" in config and "GoogleAppTokenTimestamp" in config:
        token_timestamp = datetime.datetime.fromisoformat(config["GoogleAppTokenTimestamp"])
        time_diff = datetime.datetime.now() - token_timestamp
        
        if time_diff.total_seconds() < 1800:  # Less than 30 minutes
            app_headers = {
                "Authorization": f"Bearer {config['GoogleAppToken']}",
                "x-goog-user-project": config.get('AdminProjectId', 'administration')
            }
            send_update(f"Google App Token age is OK: {int(time_diff.total_seconds() / 60)}m.", 0)
            return
        else:
            send_update(f"Google App Token is too old: {int(time_diff.total_seconds() / 60)}m.", 1)
    else:
        send_update("New token needed", 1)
    
    # Use Python's JWT library for this in a real implementation
    import base64
    import time
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    
    private_key = config["ServiceAccountKey"]
    
    # Create JWT header
    header = {
        "alg": "RS256",
        "typ": "JWT"
    }
    header_json = json.dumps(header).encode()
    header_base64 = base64.urlsafe_b64encode(header_json).decode().rstrip("=")
    
    # Create JWT claim set
    timestamp = int(time.time())
    claim_set = {
        "iss": config["ServiceAccountEmail"],
        "scope": "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/spreadsheets",
        "aud": "https://oauth2.googleapis.com/token",
        "exp": timestamp + 3600,
        "iat": timestamp
    }
    claim_set_json = json.dumps(claim_set).encode()
    claim_set_base64 = base64.urlsafe_b64encode(claim_set_json).decode().rstrip("=")
    
    # Create signature
    signature_input = f"{header_base64}.{claim_set_base64}"
    
    # This is a simplified version - in a real implementation you'd use proper RSA signing
    # Here we're using the cryptography library for proper signing
    private_key_bytes = base64.b64decode(private_key)
    private_key_obj = serialization.load_der_private_key(
        private_key_bytes, 
        password=None, 
        backend=default_backend()
    )
    
    signature = private_key_obj.sign(
        signature_input.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    signature_base64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    jwt = f"{header_base64}.{claim_set_base64}.{signature_base64}"
    
    # Get access token
    body = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": jwt
    }
    
    response = requests.post(
        "https://oauth2.googleapis.com/token", 
        data=body, 
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    
    if response.status_code == 200:
        token_data = response.json()
        app_headers = {
            "Authorization": f"Bearer {token_data['access_token']}",
            "x-goog-user-project": config.get('AdminProjectId', 'administration')
        }
        
        # Save valid token
        set_prefs("GoogleAppToken", token_data["access_token"])
        set_prefs("GoogleAppTokenTimestamp", datetime.datetime.now().isoformat())
    else:
        send_update(f"Failed to get Google API token: {response.text}", 2)

def get_group_key(group_email: str) -> str:
    """Google requires GroupKey for API calls- retrieve the key from the group name"""
    uri = f"https://admin.googleapis.com/admin/directory/v1/groups?domain=harnessevents.io&query=email='{group_email}'"
    send_update(f"Looking up key with uri: {uri}", 0)
    
    headers = {"Authorization": f"Bearer {config['GoogleAccessToken']}"}
    response = requests.get(uri, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        if "groups" in data and data["groups"] and "id" in data["groups"][0]:
            send_update(f"Group ID retrieved: {data['groups'][0]['id']}", 0)
            return data["groups"][0]["id"]
    
    send_update(f"NO ID found for URI: {uri}", 2)
    return None

def new_gcp_project() -> None:
    """Create a new GCP project for the event"""
    if args.google_cloud_project_override:
        set_prefs("GoogleProjectId", args.google_cloud_project_override)
        set_prefs("GoogleProject", "Command Line Override")
        set_prefs("GoogleRegion", "us-central1")
        project_check = send_update("Check Project Override exists", 1, 
                                  f"gcloud projects list --filter='id:{config['GoogleProjectId']}' --format=json")
        project_check = json.loads(project_check) if project_check else None
    else:
        # Use Harness Org as the project name- adjusting for the different character requirements
        set_prefs("GoogleProject", config["HarnessOrg"].replace("_", "-"))
        project_check = send_update("Check for existing project", 1, 
                                  f"gcloud projects list --filter='name:{config['GoogleProject']}' --format=json")
        project_check = json.loads(project_check) if project_check else None
    
    if args.google_cloud_project_override and not project_check:
        send_update(f"Google project override used but {args.google_cloud_project_override} doesn't exist. BYIIEEEEE.", 2)
        sys.exit(1)
    
    if project_check:
        # Project already exists- skip creation
        send_update("Project already exists- skipping creation.", 1)
        set_prefs("GoogleProjectId", project_check[0]["projectId"])
    else:
        # Get organization of admin project to assign to new project
        google_admin_ancestors = send_update("Retrieve org info", 1, 
                                           f"gcloud projects get-ancestors {config['AdminProjectId']} --format=json")
        google_admin_ancestors = json.loads(google_admin_ancestors)
        google_org_id = next((item["id"] for item in google_admin_ancestors if item["type"] == "organization"), None)
        
        # Get billing project of admin project to associate with this project
        admin_project_info = send_update("Retrieving billing account", 1, 
                                        "gcloud billing accounts list --filter=displayName='HarnessEvents' --format=json")
        admin_project_info = json.loads(admin_project_info)
        google_billing_project = admin_project_info[0]["name"].split("/")[1]
        
        # Generate a unique project ID following all of Google's rules
        if len(config["GoogleProject"]) > 16:
            set_prefs("GoogleProject", config["GoogleProject"][:16])
        
        project_id = f"event-{get_random_string()}"
        project_id = project_id.lower()
        
        send_update(f"Create {config['GoogleProject']} project", 1, 
                  f"gcloud projects create {project_id} --name=\"{config['GoogleProject']}\" --organization={google_org_id} --set-as-default -q",
                  output_suppression=True)
        
        project_details = None
        while not project_details:
            project_details = send_update("Waiting for project to be available...", 1,
                                        f"gcloud projects list --filter='name:{config['GoogleProject']}' --format=json")
            project_details = json.loads(project_details) if project_details else None
            time.sleep(6)
        
        # Associate project with billing account
        send_update("Associate billing account", 1,
                  f"gcloud billing projects link {project_id} --billing-account={google_billing_project}",
                  output_suppression=True)
        
        set_prefs("GoogleProjectId", project_details[0]["projectId"])
        
        # Add users to project
        send_update("Add group 300@harnessevents.io to project", 1,
                  f"gcloud projects add-iam-policy-binding {config['GoogleProjectId']} --member='group:300@harnessevents.io' --role='roles/owner' -q",
                  output_suppression=True)
        
        send_update("Add instructor to project", 1,
                  f"gcloud projects add-iam-policy-binding {config['GoogleProjectId']} --member='user:{config['InstructorEmail']}' --role='roles/owner' -q",
                  output_suppression=True)
        
        send_update(f"Add group {config['GoogleEventEmail']} to project", 1,
                  f"gcloud projects add-iam-policy-binding {config['GoogleProjectId']} --member='group:{config['GoogleEventEmail']}' --role='roles/editor' -q",
                  output_suppression=True)
        
        # Enable API's needed for events
        project_apis = ["compute.googleapis.com", "container.googleapis.com", "run.googleapis.com"]
        for api in project_apis:
            send_update(f"Enabling {api} API", 1, f"gcloud services enable {api}", output_suppression=True)
        
        # Wait for confirmation that API's are enabled
        counter = 0
        needed_apis = project_apis.copy()
        while needed_apis and counter < 10:
            counter += 1
            enabled_apis = send_update("", 0, "gcloud services list --format=json")
            enabled_apis = json.loads(enabled_apis)
            enabled_api_names = [api["config"]["name"] for api in enabled_apis]
            needed_apis = [api for api in project_apis if api not in enabled_api_names]
            time.sleep(2)
        
        if needed_apis:
            send_update("It took too long enabling needed API's", 2)
        
        # Create worker, get keys, add to IAM
        send_update("Create service account", 1, 
                  f"gcloud iam service-accounts create worker1 --project={config['GoogleProjectId']}", 
                  output_suppression=True)
        
        send_update("Grant service account permissions", 1,
                  f"gcloud projects add-iam-policy-binding {config['GoogleProjectId']} --member=serviceAccount:worker1@{config['GoogleProjectId']}.iam.gserviceaccount.com --role='roles/editor'",
                  output_suppression=True)
        
        send_update("Generate local key json file", 1,
                  f"gcloud iam service-accounts keys create worker1.json --iam-account=worker1@{config['GoogleProjectId']}.iam.gserviceaccount.com",
                  output_suppression=True)
        
        add_secret_json("worker1.json", "GCP_Service_Account")
    
    if os.path.exists("worker1.json"):
        os.remove("worker1.json")
    
    # Load GCP-specific templates
    add_org_yaml("./harnesseventsdata/orgGCP")
    
    # Move on to loading GCP resources
    new_gcp_resources()

def new_gcp_resources() -> None:
    """Create GCP resources for the event"""
    # Create unique Google Resource ID
    clean_identifier = ""
    if args.google_cloud_project_override:
        # We're building this cluster in a potentially shared space- use the current user as an identifier
        clean_identifier = f"-{config['GoogleUser'].split('@')[0].replace('.', '')}"
        cluster_region = "us-central1"
    else:
        cluster_region = send_update("Getting first available region", 1,
                                   f"gcloud compute regions list --filter='name:us-*' --limit=1 --format='value(NAME)' --verbosity=error --project={config['GoogleProjectId']}")
    
    # Save the identifier/region used here
    set_prefs("GoogleResourceID", f"harnessevent{clean_identifier}")
    set_prefs("GoogleRegion", cluster_region)
    
    # Create cluster if needed
    cluster_exists = send_update("Check for Google harnessevent cluster", 1,
                               f"gcloud container clusters list --filter=name={config['GoogleResourceID']} --format=json --verbosity=error --project={config['GoogleProjectId']}")
    cluster_exists = json.loads(cluster_exists) if cluster_exists else None
    
    if not cluster_exists:
        send_update("Create kubernetes cluster", 1,
                  f"gcloud container clusters create {config['GoogleResourceID']} -m e2-standard-4 --num-nodes=1 --zone={cluster_region} --no-enable-insecure-kubelet-readonly-port --scopes=cloud-platform --project={config['GoogleProjectId']}")
        
        cluster_exists = send_update("Confirm cluster exists", 1,
                                   f"gcloud container clusters list --filter=name={config['GoogleResourceID']} --format=json --project={config['GoogleProjectId']}")
        cluster_exists = json.loads(cluster_exists) if cluster_exists else None
        
        if not cluster_exists:
            send_update("Attempted to create google kubernetes cluster it failed. IT FAILED SO BAD. WHY? WHYYYYYY GOOGLE?", 2)
            sys.exit(1)
    
    send_update("Retrieve kubernetes credentials", 1,
              f"gcloud container clusters get-credentials {config['GoogleResourceID']} --zone={cluster_region} --project={config['GoogleProjectId']}",
              output_suppression=True)
    
    add_delegate("gcp")
    
    # Create google artifact registry if needed
    registry_exists = send_update("Check if Artifact Registry exists", 1,
                                f"gcloud artifacts repositories list --filter={config['GoogleResourceID']} --project={config['GoogleProjectId']} --format=json")
    registry_exists = json.loads(registry_exists) if registry_exists else None
    
    if registry_exists:
        send_update("Registry exists- skipping create", 0)
    else:
        # Create Google artifact registry
        send_update("Create google artifact registry", 1,
                  f"gcloud artifacts repositories create {config['GoogleResourceID']} --repository-format=docker --location={config['GoogleRegion']} --project={config['GoogleProjectId']}")

def add_delegate(delegate_prefix: str) -> None:
    """Add a delegate to the Kubernetes cluster"""
    # Implementation of delegate addition would go here
    send_update(f"Adding {delegate_prefix} delegate to cluster", 1)
    # This would involve Kubernetes manifest creation and application

def add_org_yaml(yaml_folder: str) -> None:
    """Load organization YAML templates"""
    send_update(f"Loading organization YAML from {yaml_folder}", 1)
    # Implementation would involve loading and processing YAML files

def add_secret_json(file_name: str, secret_id: str) -> None:
    """Add a JSON file as a secret"""
    send_update(f"Adding {file_name} as secret {secret_id}", 1)
    # Implementation would involve adding the file content as a secret

def show_help() -> None:
    """Display help information"""
    print()
    print("Action required. Options are 'create' or 'remove'.")
    print("example: python harnessevents.py create")
    print()

def get_headless_mode() -> None:
    """Create a new event"""
    send_update("Entering headless (create) mode", 1)
    # Implementation of event creation would go here

def get_janitor_mode() -> None:
    """Remove expired events"""
    send_update("Entering janitor (remove) mode", 1)
    # Implementation of event cleanup would go here

def main():
    """Main entry point for the script"""
    script_path = os.path.splitext(os.path.abspath(__file__))[0]
    test_preflight()
    get_prefs(script_path)
    
    if args.action == "create":
        get_headless_mode()
    elif args.action == "remove":
        get_janitor_mode()
    else:
        show_help()

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Harness Events Script")
    parser.add_argument("action", nargs="?", help="Action to execute (create or remove)")
    parser.add_argument("--aws", action="store_true", help="[CREATE MODE] create aws classroom for event")
    parser.add_argument("--azure", action="store_true", help="[CREATE MODE] create azure classroom for event")
    parser.add_argument("--cloud-commands", action="store_true", help="Enable to show commands")
    parser.add_argument("--harness-custom-pat", help="[CREATE MODE] harness PAT (default is community HarnessEvents account)")
    parser.add_argument("--gcp", action="store_true", help="[CREATE MODE] create gcp classroom for event")
    parser.add_argument("--google-cloud-project-override", help="Override project creation to use a specific project")
    parser.add_argument("--hour-limit", type=int, help="[REMOVE MODE] max event lifespan in hours (WARNING: THIS AFFECTS ALL EVENTS)")
    parser.add_argument("--event-name", help="[CREATE MODE] specify event name")
    parser.add_argument("--instructor-name", help="[CREATE MODE] specify instructorName (defaults to current user)")
    parser.add_argument("--verbose-mode", action="store_true", help="Level 0 (debug/info/errors) output (versus standard level 1 info/errors)")
    parser.add_argument("--user-count", type=int, default=3, help="[CREATE MODE] specify number of attendees (default is 3)")
    
    args = parser.parse_args()
    
    main()
