from flask import Blueprint, jsonify

default_routes = Blueprint("default_routes", __name__)


@default_routes.route("/", defaults={"path": ""})
def base_route(path):
    data = 
    return jsonify(data)
