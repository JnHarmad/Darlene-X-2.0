import zipfile
import yara
import json
from django.http import JsonResponse
from androguard.misc import AnalyzeAPK
from .values import ANDROID_PERMISSIONS, SUSPICIOUS_APIS
import time
import os
import uuid
import requests
from django.conf import settings


def _compile_yara_rules_from_path(yara_rules_path):
    """
    Compile YARA rules from a single file or a directory containing multiple
    rule files. Returns a compiled rules object or raises yara.Error.
    """
    if not yara_rules_path:
        return None

    if os.path.isdir(yara_rules_path):
        rule_file_paths = {}
        for root, _dirs, files in os.walk(yara_rules_path):
            for filename in files:
                if filename.lower().endswith((".yar", ".yara")):
                    full_path = os.path.join(root, filename)
                    # Use a stable key name for each rule file
                    key = os.path.relpath(full_path, yara_rules_path)
                    rule_file_paths[key] = full_path
        if not rule_file_paths:
            return None
        return yara.compile(filepaths=rule_file_paths)
    else:
        # Single file fallback
        return yara.compile(filepath=yara_rules_path)


def analyze_apk_step_1(apk_file,unique_id, yara_rules_path=None):
    """
    Step 1 analyzer:
    - Extract manifest info
    - Detect suspicious API calls (from model list)
    - Detect suspicious files
    - Optional YARA verification
    Returns (success: bool, JsonResponse | None, dict | None).
    """
    start_time = time.time()  # Start the timer

    try:
        # -------- Step 1: Load APK with Androguard --------
        try:
            a, d, dx = AnalyzeAPK(apk_file)  # a=APK object, d=DEX, dx=Analysis
        except Exception as e:
            return (False,JsonResponse({"error": "Failed to parse APK file.", "details": str(e)}, status=400),None,)

        # -------- Manifest Data Extraction --------
        manifest_data = {
            "package": a.get_package(),
            "min_sdk": a.get_min_sdk_version(),
            "target_sdk": a.get_target_sdk_version(),
            "permissions": a.get_permissions(),
            "activities": a.get_activities(),
            "receivers": a.get_receivers(),
            "providers": a.get_providers(),
            "certificates": [c.sha256_fingerprint.replace(":", "") for c in a.get_certificates()],
        }

        # -------- Step 2: Suspicious API Scan --------
        suspicious_calls = []
        try:
            for cls in d[0].get_classes():  # check first dex
                for method in cls.get_methods():
                    code = method.get_code()
                    if not code:
                        continue
                    for insn in code.get_bc().get_instructions():
                        op = insn.get_output()
                        for api in SUSPICIOUS_APIS:
                            if api in op:
                                suspicious_calls.append({
                                    "class": cls.get_name(),
                                    "method": method.get_name(),
                                    "api": api,
                                })
        except Exception as e:
            return (False,JsonResponse({"error": "Failed to scan for suspicious API calls.", "details": str(e)}, status=500),None,)

        # -------- Step 3: Suspicious Permissions Scan --------
        suspicious_permissions = []
        try:
            apk_permissions = set(a.get_permissions())
            for perm in ANDROID_PERMISSIONS:
                if perm in apk_permissions:
                    suspicious_permissions.append(perm)
        except Exception as e:
            return (False,JsonResponse({"error": "Failed to scan for suspicious permissions.", "details": str(e)}, status=500),None,)

        
        # -------- Step 4: Optional YARA Verification --------
        yara_results = []
        skipped_encrypted_files = []
        if yara_rules_path:
            try:
                rules = _compile_yara_rules_from_path(yara_rules_path)
                if rules:
                    # Scan all files inside the APK using Androguard's APK interface
                    try:
                        for name in a.get_files():
                            try:
                                data = a.get_file(name)
                                if data is None:
                                    continue
                                matches = rules.match(data=data)
                                if matches:
                                    yara_results.append({
                                        "file": name,
                                        "matches": [m.rule for m in matches],
                                    })
                            except Exception:
                                # Skip unreadable entries, continue scanning others
                                continue
                    except Exception as inner_apk_err:
                        return (False, JsonResponse({"error": "Failed to read APK contents via Androguard.", "details": str(inner_apk_err)}, status=500), None,)

                    # Additionally scan raw DEX buffers obtained via Androguard analysis
                    try:
                        for idx, dex in enumerate(d):
                            try:
                                dex_bytes = dex.get_buff()
                            except Exception:
                                dex_bytes = None
                            if not dex_bytes:
                                continue
                            matches = rules.match(data=dex_bytes)
                            if matches:
                                yara_results.append({
                                    "file": f"classes{idx + 1}.dex",
                                    "matches": [m.rule for m in matches],
                                })
                    except Exception:
                        # If DEX scanning fails, proceed without blocking the rest
                        pass
            except yara.Error as e:
                return (False, JsonResponse({"error": "Failed to apply YARA rules.", "details": str(e)}, status=500), None,)
            except Exception as e:
                return (False, JsonResponse({"error": "Error during YARA verification.", "details": str(e)}, status=500), None,)

        # -------- Final Result --------
        end_time = time.time()  # End the timer
        runtime = end_time - start_time

        analysis_result = {
            "manifest": manifest_data,
            "suspicious_api_calls": suspicious_calls,
            "suspicious_permissions": suspicious_permissions,
            "yara_matches": yara_results,
            "yara_skipped_encrypted_files": skipped_encrypted_files,
            "runtime_seconds": round(runtime, 2),  # runtime in seconds
        }

        return True, None, analysis_result

    except Exception as e:
        return (
            False,
            JsonResponse({"error": "An unexpected error occurred.", "details": str(e)}, status=500),
            None,
        )


def analyze_apk_step_2(analysis_path):
    """
    Step 2 analyzer:
    Generate binary vector (0/1) for suspicious permissions and APIs
    based on FEATURE_LIST.
    """
    with open(analysis_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Extract relevant lists
    sus_perms = set(data["data"].get("suspicious_permissions", []))
    sus_apis = {call["api"] for call in data["data"].get("suspicious_api_calls", [])}

    vector = []
    for feature in ANDROID_PERMISSIONS + SUSPICIOUS_APIS: # these are the feature list
        if feature in sus_perms or feature in sus_apis:
            vector.append(1)
        else:
            vector.append(0)

    return vector


# fucntion to generate report and use the variable passed on to and use it for analysis
def report_generator(VT_DATA,ML_DATA,SA_JSON_PATH,APK_NAME,ID): 
    


    status = "Success"  # if all task done
    #pdf file name  suggestion : report_apk-name_ID.pdf
    pdf_path = "set it path of the pdf"  
    return pdf_path , status


def VirusTotalDataCall(APK_SHA256, APK_PATH, ID):
    VT_API = getattr(settings, 'VT_API', None)
    VT_API_KEY = getattr(settings, 'VT_API_KEY', None)

    url = f"{VT_API}files/{APK_SHA256}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        vt_data = response.json()
        result = {
            "FileInfo": {
                "SHA256": vt_data.get("data", {}).get("id", ""),
                "MD5": vt_data.get("data", {}).get("attributes", {}).get("md5", ""),
                "Size": vt_data.get("data", {}).get("attributes", {}).get("size", 0),
                "SHA1": vt_data.get("data", {}).get("attributes", {}).get("sha1", ""),
            },
            "MaliciousCount": vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
            "MaliciousDetections": [
                {
                    "Engine": detection.get("engine_name", ""),
                    "Result": detection.get("result", ""),
                }
                for detection in vt_data.get("data", {}).get("attributes", {}).get("last_analysis_results", {}).values()
                if detection.get("category") == "malicious"
            ],
        }

        # Save the result to a JSON file
        vt_data_path = f"static/vt_data/virustotal_{ID}.json"
        os.makedirs(os.path.dirname(vt_data_path), exist_ok=True)
        with open(vt_data_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4)

        return {"vt_data_path": vt_data_path, "status": True}

    except requests.exceptions.RequestException as e:
        error_message = str(e)
        if "The resource you are requesting could not be found" in error_message:
            print("File not found, attempting to upload via virustotal_upload()")
            vt_data = virustotal_upload_scan(VT_API, VT_API_KEY, APK_PATH)
            if vt_data:
                result = {
                    "FileInfo": {
                        "SHA256": vt_data.get("data", {}).get("id", ""),
                        "MD5": vt_data.get("data", {}).get("attributes", {}).get("md5", ""),
                        "Size": vt_data.get("data", {}).get("attributes", {}).get("size", 0),
                        "SHA1": vt_data.get("data", {}).get("attributes", {}).get("sha1", ""),
                    },
                    "MaliciousCount": vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
                    "MaliciousDetections": [
                        {
                            "Engine": detection.get("engine_name", ""),
                            "Result": detection.get("result", ""),
                        }
                        for detection in vt_data.get("data", {}).get("attributes", {}).get("last_analysis_results", {}).values()
                        if detection.get("category") == "malicious"
                    ],
                }
                vt_data_path = f"static/vt_data/virustotal_{ID}.json"
                os.makedirs(os.path.dirname(vt_data_path), exist_ok=True)
                with open(vt_data_path, "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=4)

                return {"vt_data_path": vt_data_path, "status": True}
            else:
                return {"vt_data_path": "", "status": False}
        else:
            print(f"Error during VirusTotal API call: {e}")
        return {"vt_data_path": "", "status": False}

def VirusTotalCheck(APK_SHA256):
    VT_API = getattr(settings, 'VT_API', None)
    VT_API_KEY = getattr(settings, 'VT_API_KEY', None)

    url = f"{VT_API}files/{APK_SHA256}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        return True

    except requests.exceptions.RequestException as e:
        error_message = str(e)
        if "The resource you are requesting could not be found" in error_message:
            return False
            
        else:
            print(f"Error during VirusTotal API call: {e}")
        return False



def virustotal_upload_scan(VT_API, VT_API_KEY, APK_PATH):
    # Step 1: Get upload URL for VirusTotal
    url = f"{VT_API}files/upload_url"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        upload_url = data.get("data")

        if not upload_url:
            print("Failed to retrieve upload URL from VirusTotal.")
            return False

        # Step 2: Upload APK to VirusTotal
        with open(APK_PATH, "rb") as apk_file:
            files = {"file": apk_file}
            upload_response = requests.post(upload_url, headers=headers, files=files)
            upload_response.raise_for_status()
            upload_result = upload_response.json()

            # Step 3: Extract analysis link and send request
            analysis_link = upload_result.get("data", {}).get("links", {}).get("self")
            if analysis_link:
                for attempt in range(7):  # Retry up to 5 times
                    analysis_response = requests.get(analysis_link, headers=headers)
                    analysis_response.raise_for_status()
                    analysis_result = analysis_response.json()
                    status = analysis_result.get("data", {}).get("attributes", {}).get("status", "")

                    if status != "queued":
                        return analysis_result
                    print(f"Status is 'queued', retrying... (Attempt {attempt + 1}/7)")
                    time.sleep(15)

                print("Analysis did not complete after 5 attempts.")
                return False
            else:
                print("Failed to retrieve analysis link.")
                return False

    except requests.exceptions.RequestException as e:
        print(f"Error during VirusTotal upload: {e}")
        return False