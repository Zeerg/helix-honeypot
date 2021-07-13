from flask import Flask, jsonify, request
from routes.api_routes import api_routes
from routes.pod_routes import pod_routes
from routes.default import default_routes


app= Flask(__name__)
app.register_blueprint(api_routes)
app.register_blueprint(pod_routes)
app.register_blueprint(default_routes)


#  main thread of execution to start the server

if __name__=='__main__':
    app.run(debug=True)