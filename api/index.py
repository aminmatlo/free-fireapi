from flask import Flask, request, Response
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from protobuf_decoder.protobuf_decoder import Parser
import json

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type == "varint":
            field_data['data'] = result.data
        if result.wire_type == "string":
            field_data['data'] = result.data
        if result.wire_type == "bytes":
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None
def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()    

def decrypt_api(cipher_text):
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(bytes.fromhex(cipher_text)), AES.block_size)
    return plain_text.hex()    

app = Flask(__name__)

def MajorLogin(payload, headers):
    url = "https://loginbp.ggpolarbear.com/MajorLogin"

    headers = dict(headers)
    headers.pop("Host", None)
    headers.pop("Content-Length", None)

    response = requests.post(url, headers=headers, data=payload, verify=False)
    return response.content


@app.route('/MajorLogin', methods=['POST'])
def MajorLoginProxy():
    payload = request.get_data()
    headers = request.headers

    response_data = MajorLogin(payload, headers)
    return b'\x08\xba\xc3\xbf\x8d(\x12\x02ME\x1a\x02ME"\x02MA*\x04liveB\x86\x06eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjoxMDc2NTcyMjA0Miwibmlja25hbWUiOiLYp9mE2YbYtdin2KgwITdaNiIsIm5vdGlfcmVnaW9uIjoiTUUiLCJsb2NrX3JlZ2lvbiI6Ik1FIiwiZXh0ZXJuYWxfaWQiOiIxNmY2NDc0ZjliN2I5M2U2NTM5NWI5OTY4YmI3MTdjMiIsImV4dGVybmFsX3R5cGUiOjQsInBsYXRfaWQiOjEsImNsaWVudF92ZXJzaW9uIjoiMS4xMTQuMSIsImVtdWxhdG9yX3Njb3JlIjowLCJpc19lbXVsYXRvciI6ZmFsc2UsImNvdW50cnlfY29kZSI6Ik1BIiwiZXh0ZXJuYWxfdWlkIjozNjg4NzU5MTA2LCJyZWdfYXZhdGFyIjoxMDIwMDAwMDcsInNvdXJjZSI6MCwibG9ja19yZWdpb25fdGltZSI6MTczNjY5NDUwNCwiY2xpZW50X3R5cGUiOjIsInNpZ25hdHVyZV9tZDUiOiJlODliMTU4ZTRiY2Y5ODhlYmQwOWViODNmNTM3OGU4NyIsInVzaW5nX3ZlcnNpb24iOjIsInJlbGVhc2VfY2hhbm5lbCI6ImFuZHJvaWRfbWF4IiwicmVsZWFzZV92ZXJzaW9uIjoiT0I1MSIsImV4cCI6MTc2NDU0NzE3Mn0.3-px2Dd626XPqSyYOJINt1-jCDcpxqFcxafj_Tj_NFMH\x80\xe1\x01R\x1fhttps://free-fireapi.vercel.appz\x02\x08\x01\x82\x01]csoversea.stronghold.freefiremobile.com;34.126.76.45;34.87.177.14;34.87.170.230;35.185.183.57\x9a\x01\x06Agadir\xa2\x01\x0209\xa8\x01\xe4\xd3\xb1\xc9\x06\xb2\x01\x10\x9e\x86\xae\xfcI\x7fi\xf7P\x1e%(B C1\xba\x01\x10\xaf\xbe\xdd\xf2yo{\xf2t3%@D A2\xc2\x01]csoversea.stronghold.freefiremobile.com;34.126.76.45;34.87.177.14;34.87.170.230;35.185.183.57\xca\x01\x08\n\x02ME\x10\x01(\x01'
    #return response_data

def GetLoginData(payload, headers):
    url = "https://loginbp.ggpolarbear.com/GetLoginData"

    headers = dict(headers)
    headers.pop("Host", None)
    headers.pop("Content-Length", None)

    response = requests.post(url, headers=headers, data=payload, verify=False)
    return response.content


@app.route('/GetLoginData', methods=['POST'])
def GetLoginDataLoginProxy():
    payload = request.get_data()
    headers = request.headers

    x = decrypt_api(payload.hex())
    json_result = get_available_room(x)
    parsed_data = json.loads(json_result)

    NEW_ACCESS_TOKEN = parsed_data["29"]["data"]
    NEW_EXTERNAL_ID = parsed_data["22"]["data"]

    PAYLOAD = (
        b':\x071.118.1'
        b'\xaa\x01\x02ar'
        b'\xb2\x01 55ed759fcf94f85813e57b2ec8492f5c'
        b'\xba\x01\x014'
        b'\xea\x01@6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae'
        b'\x9a\x06\x014'
        b'\xa2\x06\x014'
    )

    PAYLOAD = PAYLOAD.replace(
        b"6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae",
        NEW_ACCESS_TOKEN.encode("utf-8")
    )

    PAYLOAD = PAYLOAD.replace(
        b"55ed759fcf94f85813e57b2ec8492f5c",
        NEW_EXTERNAL_ID.encode("utf-8")
    )

    PAYLOAD = PAYLOAD.hex()
    PAYLOAD = encrypt_api(PAYLOAD)
    PAYLOAD = bytes.fromhex(PAYLOAD)

    response_data = GetLoginData(PAYLOAD, headers)
    return response_data
