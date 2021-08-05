import os
import io
from flask import Blueprint, jsonify, render_template, make_response, request, send_file
import gzip
# Need to build this https://github.com/kubernetes/kube-openapi/blob/master/pkg/handler/handler.go#L205

openapi_routes = Blueprint("openapi_routes", __name__, url_prefix="/openapi")


@openapi_routes.route("/v2", methods=["GET"])
def open_api_route():
    # Vary Response Based on User Agent it's actually a protobuf https://sourcegraph.com/github.com/kubernetes/kube-openapi@dd2c4a2dc3ff0acdd86ca5a0b5b5782697bcee82/-/blob/pkg/handler/handler.go?L194:6
    user_agent = request.headers.get('User-Agent')
    if 'kube' in str(user_agent):
        with open(os.path.abspath(os.path.dirname(__file__)) + '/openapi.txt', 'rb') as f:
                response = make_response(send_file(io.BytesIO(gzip.compress(f.read(), 1)), mimetype='application/octet-stream', add_etags=True))
                response.headers['Content-Encoding'] = 'gzip'
                return response
    else:
        with open(os.path.abspath(os.path.dirname(__file__)) + '/openapi.json', 'rb') as f:
            response = make_response(send_file(io.BytesIO(f.read())))
            return response
