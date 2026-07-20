import uuid
from django.http import JsonResponse
from django.views import View
import os
import json
from django.conf import settings
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
import magic
from .models import UploadedAPK , Analysis
import hashlib
from django.utils.decorators import method_decorator
from .modules.function import VirusTotalCheck, VirusTotalDataCall, analyze_apk_step_1 , analyze_apk_step_2 , report_generator
from .modules.ml_analysis import predict

class UploadApkView(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('TRUSTIFY '):
            return JsonResponse({'error': 'Missing or invalid Authorization header'}, status=401)
        
        auth_token = auth_header.split('TRUSTIFY ')[-1].strip()
        expected_token = getattr(settings, 'AUTH_TOKEN', None)
        if auth_token != expected_token:
            return JsonResponse({'error': 'Forbidden'}, status=403)

        if 'file' not in request.FILES:
            return JsonResponse({'error': 'No file provided'}, status=400)

        apk_file = request.FILES['file']

        if apk_file == "":
            return JsonResponse({'error': 'No file provided'}, status=400)
        
        # Check file size (limit: 500 MB)
        max_file_size = 500 * 1024 * 1024  # 500 MB in bytes
        if apk_file.size > max_file_size:
            return JsonResponse({'warning': 'File size exceeds 500 MB. The file may be bad or infected.'}, status=400)

        # Null File check
        apk_file.seek(0, 2)
        file_size = apk_file.tell()
        apk_file.seek(0)

        if file_size == 0:
            return JsonResponse({'error': 'File uploaded was empty !'}, status=400)
        # Read the first few bytes of the file to check the magic bits
        file_header = apk_file.read(4)
        apk_file.seek(0)

        valid_magic_bits = [
            b'PK\x03\x04',  # Standard APK
            b'PK\x05\x06',  # Empty archive
            b'PK\x07\x08',  # Spanned archive
        ]

        if file_header not in valid_magic_bits:
            return JsonResponse({'error': 'Invalid APK file'}, status=400)

        # Optionally, you can use the `python-magic` library to verify MIME type
        mime = magic.Magic(mime=True)
        mime_type = mime.from_buffer(apk_file.read(2048))
        apk_file.seek(0)  # Reset file pointer after reading

        # Allowed mime types
        valid_mime_types = [
            "application/zip",
            "application/java-archive",
            "application/vnd.android.package-archive",
            "application/octet-stream"
        ]

        if mime_type not in valid_mime_types:
            return JsonResponse({'error': f'File is not a valid APK (detected: {mime_type})'}, status=400)

        # Calculate the hash of the file using SHA-256
        hash_sha256 = hashlib.sha256()
        for chunk in apk_file.chunks():
            hash_sha256.update(chunk)
        apk_hash = hash_sha256.hexdigest()

        # Check if the file already exists in the database
        existing_apk = UploadedAPK.objects.filter(file_hash=apk_hash).first()
        if existing_apk:
            return JsonResponse({'success': 'File already exists', 'id': str(existing_apk.id)}, status=200)

        save_path = os.path.join(settings.BASE_DIR, "static", "uploadedAPK")
        os.makedirs(save_path, exist_ok=True)
        file_path = os.path.join(save_path, apk_file.name)

        with open(file_path, 'wb+') as destination:
            for chunk in apk_file.chunks():
                destination.write(chunk)

        # Save upload info to database
        unique_id = uuid.uuid4()
        UploadedAPK.objects.create(
            id=unique_id,
            file_name=apk_file.name,
            file_path=file_path,
            file_hash=apk_hash,
            processed=False
        )

        return JsonResponse({'success': 'APK uploaded successfully', 'id': str(unique_id)}, status=200)

class VirusTotal(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('TRUSTIFY '):
            return JsonResponse({'error': 'Missing or invalid Authorization header'}, status=401)

        uuid_str = auth_header.split('TRUSTIFY ')[-1].strip()
        try:
            apk_uuid = uuid.UUID(uuid_str)
        except Exception:
            return JsonResponse({'error': 'Invalid UUID format'}, status=400)

        # Fetch APK record
        apk_record = UploadedAPK.objects.filter(id=apk_uuid).first()

        if not apk_record:
            return JsonResponse({'error': 'No APK found for this UUID'}, status=404)

        APK_PATH = apk_record.file_path

        if apk_record.vt_data_path:
            return JsonResponse({'success': 'VirusTotal exec Successful!'}, status=200)
        else:
            APK_SHA256 = apk_record.file_hash

            result = VirusTotalDataCall(APK_SHA256, APK_PATH, apk_uuid)
            vt_data_path = result.get("vt_data_path", "")
            status = result.get("status", False)
            if status:
                # Save the VirusTotal data path to the database
                apk_record.vt_data_path = vt_data_path
                apk_record.save()
                return JsonResponse({'success': 'VirusTotal exec Successful!'}, status=200)
            else:
                return JsonResponse({'error': 'Failed to execute VirusTotal'}, status=404)


class VirusCheck(View):
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('TRUSTIFY '):
            return JsonResponse({'error': 'Missing or invalid Authorization header'}, status=401)

        uuid_str = auth_header.split('TRUSTIFY ')[-1].strip()
        try:
            apk_uuid = uuid.UUID(uuid_str)
        except Exception:
            return JsonResponse({'error': 'Invalid UUID format'}, status=400)

        # Fetch APK record
        apk_record = UploadedAPK.objects.filter(id=apk_uuid).first()

        if not apk_record:
            return JsonResponse({'error': 'No APK found for this UUID'}, status=404)

        if apk_record.vt_data_path:
            return JsonResponse({'success': 'VirusTotal exec Successful!'}, status=200)
        else:
            APK_SHA256 = apk_record.file_hash

            status = VirusTotalCheck(APK_SHA256)
            
            if status:
                return JsonResponse({'status': True}, status=200)
            else:
                return JsonResponse({'status': False}, status=404)

@method_decorator(csrf_exempt, name='dispatch')
class StaticAnalyzeApk(View):
    def get(self, request):
        # Get Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('TRUSTIFY '):
            return JsonResponse({'error': 'Missing or invalid Authorization header'}, status=401)

        uuid_str = auth_header.split('TRUSTIFY ')[-1].strip()
        try:
            apk_uuid = uuid.UUID(uuid_str)
        except Exception:
            return JsonResponse({'error': 'Invalid UUID format'}, status=400)

        # Fetch APK record
        apk_record = UploadedAPK.objects.filter(id=apk_uuid).first()
        if not apk_record:
            return JsonResponse({'error': 'No APK found for this UUID'}, status=404)

        # File path
        file_path = apk_record.file_path
        if not os.path.exists(file_path):
            return JsonResponse({'error': 'File not found on server'}, status=404)


        # If the analysis already exists then it will directly respond with positive response to save time and mem
        analysised_json = Analysis.objects.filter(uploaded_apk=apk_record).first()
        if analysised_json and analysised_json.processed:
            return JsonResponse({
                "message": "Analysis completed and saved!"
            }, status=200)

        # Run analysis (include YARA rules dir if present)
        yara_rules_dir = getattr(settings, 'YARA_RULES_DIR', None)
        success, response, data = analyze_apk_step_1(file_path, str(apk_uuid), yara_rules_path=yara_rules_dir)
        if not success:
            return response

        # Build final result
        final_result = {
            "message": "Analysis successful!",
            "uuid": str(apk_uuid),
            "data": data,
        }

        # -------- Save result as JSON --------
        try:
            # Make sure analysis directory exists

            apk_name = os.path.basename(file_path).replace(" ", "_")
            analysis_dir = os.path.join("static", "analysis",str(apk_name)+"_"+str(apk_uuid))
            os.makedirs(analysis_dir, exist_ok=True)
            filename = f"info.json"
            file_out_path = os.path.join(analysis_dir, filename)

            # Save JSON
            with open(file_out_path, "w", encoding="utf-8") as f:
                json.dump(final_result, f, indent=4)

            analysis_record, created = Analysis.objects.update_or_create(
                uploaded_apk=apk_record,
                defaults={
                    'analysis_path': file_out_path,
                    'processed': True,
                    'final_report_path': None
                }
            )
        except Exception as e:
            return JsonResponse(
                {"error": "Failed to save analysis result", "details": str(e)},
                status=500,
            )

        # Return only path instead of full data
        return JsonResponse({
            "message": "Analysis completed and saved!"
        }, status=200)


@method_decorator(csrf_exempt, name='dispatch')
class MlAnalyzeApk(View):
    def get(self, request):
        # Get Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('TRUSTIFY '):
            return JsonResponse({'error': 'Missing or invalid Authorization header'}, status=401)

        uuid_str = auth_header.split('TRUSTIFY ')[-1].strip()
        try:
            apk_uuid = uuid.UUID(uuid_str)
        except Exception:
            return JsonResponse({'error': 'Invalid UUID format'}, status=400)

        # Fetch APK record
        apk_record = UploadedAPK.objects.filter(id=apk_uuid).first()
        if not apk_record:
            return JsonResponse({'error': 'No APK found for this UUID'}, status=404)

        analysised_json = Analysis.objects.filter(uploaded_apk=apk_record).first()
        if not analysised_json:
            return JsonResponse({'error': 'No analysis found for this APK !'}, status=404)
        
        path = analysised_json.analysis_path
        if not os.path.exists(path):
            return JsonResponse({'error': 'Analysis file not found on server'}, status=404)
        
        analysised_json_vector = analyze_apk_step_2(path)

        if not analysised_json_vector:
            return JsonResponse({'error': 'Unable to get Vector set for ML-Analysis'}, status=404)

        response = predict(analysised_json_vector)
        return JsonResponse({
            "message": "Vector Set Ready for ML", "ML-Analysis": response
        }, status=200)


@method_decorator(csrf_exempt, name='dispatch')
class Report(View):
    def get(self, request):
        # Get Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('TRUSTIFY '):
            return JsonResponse({'error': 'Missing or invalid Authorization header'}, status=401)

        uuid_str = auth_header.split('TRUSTIFY ')[-1].strip()
        try:
            apk_uuid = uuid.UUID(uuid_str)
        except Exception:
            return JsonResponse({'error': 'Invalid UUID format'}, status=400)

        apk_record = UploadedAPK.objects.filter(id=apk_uuid).first()
        
        if not apk_record:
            return JsonResponse({'error': 'No APK found for this UUID'}, status=404)
        APK_NAME = apk_record.file_name
        ID = apk_uuid
        # Check if virus total analysis is there or not
        if not apk_record.vt_data_path:
            VT_DATA = {"status":"Virus total analysis not available !"}
        else :
            VT_DATA = apk_record.vt_data_path

        analysised_json = Analysis.objects.filter(uploaded_apk=apk_record).first()
        if not analysised_json :
            return JsonResponse({'error': 'No static analysis done yet !'}, status=404)
        
        if not analysised_json.ml_data_response:
            ML_DATA = {"status":"Machine Learning analysis not available !"}
        else :
            ML_DATA = analysised_json.ml_data_response

        path = analysised_json.analysis_path
        if not os.path.exists(path):
            return JsonResponse({'error': 'Analysis file not found on server'}, status=404)
        else:
            SA_JSON_PATH = path # SA means Static Analysis
            
        pdf_path , status = report_generator(VT_DATA,ML_DATA,SA_JSON_PATH,APK_NAME,ID)

        if status != "Success":
            return JsonResponse({
                "error": "Final report generation and over all analysis failed !"
            }, status=400)
        
        return JsonResponse({
            "message": "Final report generation and over all analysis complete.", "pdf-report": pdf_path
        }, status=200)