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
    return response_data

def GetLoginData(payload, headers):
    url = "https://loginbp.ggpolarbear.com/GetLoginData"

    headers = dict(headers)
    headers.pop("Host", None)
    headers.pop("Content-Length", None)

    response = requests.post(url, headers=headers, data=payload, verify=False)
    return response.content

@app.route('/GetLoginData', methods=['POST'])
def MajorLoginProxy():
    payload = request.get_data()
    headers = request.headers
    x = decrypt_api(payload.hex())
    json_result = get_available_room(x)
    parsed_data = json.loads(json_result)
    NEW_ACCESS_TOKEN = parsed_data["29"]["data"]
    NEW_EXTERNAL_ID = parsed_data["22"]["data"]
    PAYLOAD = b':\x071.118.1\xaa\x01\x02ar\xb2\x01 55ed759fcf94f85813e57b2ec8492f5c\xba\x01\x014\xea\x01@6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae\x9a\x06\x014\xa2\x06\x014'
    PAYLOAD = PAYLOAD.replace(b"6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae", NEW_ACCESS_TOKEN.encode("UTF-8"))
        PAYLOAD = PAYLOAD.replace(b"55ed759fcf94f85813e57b2ec8492f5c", NEW_EXTERNAL_ID.encode("UTF-8"))
PAYLOAD = PAYLOAD.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
    response_data = MajorLogin(PAYLOAD, headers)
    return response_data
