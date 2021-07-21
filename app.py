from flask import Flask, jsonify, request
from routes.api_routes import api_routes
from routes.pod_routes import pod_routes
from routes.default import default_routes
from routes.openapi import openapi_routes


helix_honeypot = Flask(__name__)
helix_honeypot.register_blueprint(api_routes)
helix_honeypot.register_blueprint(pod_routes)
helix_honeypot.register_blueprint(default_routes)
helix_honeypot.register_blueprint(openapi_routes)

if __name__ == "__main__":
    helix_honeypot.run(debug=False)
