from flask import Flask, jsonify, request
from routes.api_routes import api_routes
from routes.pod_routes import pod_routes
# initialize our Flask application
# https://github.com/kubernetes-client/python/blob/d8f283e7483848647804eab345645106b6fb357d/kubernetes/README.md
app= Flask(__name__)
app.register_blueprint(api_routes)
app.register_blueprint(pod_routes)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return 'You want path: %s' % path


#  main thread of execution to start the server

if __name__=='__main__':
    app.run(debug=True)