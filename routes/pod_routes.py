from flask import Blueprint, jsonify
from templates.kube_system import system_pods

pod_routes = Blueprint("pod_routes", __name__)


@pod_routes.route("/api/v1/namespaces/default/pods", methods=["GET"])
def get_pods_default():
    data = {
        "apiVersion": "v1",
        "items": [],
        "kind": "List",
        "metadata": {"resourceVersion": "", "selfLink": ""},
    }
    return jsonify(data)


@pod_routes.route("/api/v1/namespaces/kube-system/pods", methods=["GET"])
def get_pods_kubesystem():
    return jsonify(system_pods)
