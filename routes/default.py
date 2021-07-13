from flask import Blueprint, jsonify

default_routes = Blueprint('default_routes', __name__)

@default_routes.route('/', defaults={'path': ''})
@default_routes.route('/<path:path>')
def catch_all(path):
    return jsonify({"error":"Access Denied"})