import os
import io
from flask import Blueprint, jsonify, render_template, make_response, request, send_file
import gzip

# Need to build this https://github.com/kubernetes/kube-openapi/blob/3c818078ee3de6569a8f02b6345ea3c4cc8b0998/pkg/handler/handler.go#L117

openapi_routes = Blueprint("openapi_routes", __name__, url_prefix="/openapi")


@openapi_routes.route("/v2", methods=["GET"])
def open_api_route():
    # Vary Response Based on User Agent
    user_agent = request.headers.get("User-Agent")
    if "kube" in user_agent:
        with open(
            os.path.abspath(os.path.dirname(__file__)) + "/openapi.json", "rb"
        ) as f:
            response = make_response(
                send_file(
                    io.BytesIO(gzip.compress(f.read(), 5)),
                    mimetype="application/octet-stream",
                )
            )
            response.headers["Content-Encoding"] = "gzip"
            response.add
            return response
    else:
        with open(
            os.path.abspath(os.path.dirname(__file__)) + "/openapi.json", "rb"
        ) as f:
            response = make_response(
                send_file(io.BytesIO(f.read()), mimetype="text/plain")
            )
            return response
