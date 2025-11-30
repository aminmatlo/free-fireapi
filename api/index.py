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
