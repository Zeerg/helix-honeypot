from flask import Blueprint, jsonify

pod_routes = Blueprint('pod_routes', __name__)

@pod_routes.route("/api/v1/namespaces/default/pods", methods=["GET"])
def get_pods():
    data = {
    "apiVersion": "v1",
    "items": [],
    "kind": "List",
    "metadata": {
        "resourceVersion": "",
        "selfLink": ""
    }
}
    return jsonify(data)