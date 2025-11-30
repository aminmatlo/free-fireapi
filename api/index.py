from flask import Flask, request, Response
import requests
from data_pb2 import Data

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
    data_bytes = bytes.fromhex(response_data.hex())
    packet = Data()
    packet.ParseFromString(data_bytes)
    packet.field10 = "https://free-fireapi.vercel.app"
    return packet.SerializeToString()
