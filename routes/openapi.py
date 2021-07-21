import os

from flask import Blueprint, jsonify, render_template, make_response


openapi_routes = Blueprint("openapi_routes", __name__, url_prefix="/openapi")


@openapi_routes.route("/v2", methods=["GET"])
def open_api_route():

    with open(os.path.abspath(os.path.dirname(__file__)) + '/openapi.json') as f:
        resp = make_response(render_template('openapi.html', text=f.read()))
        resp.headers['Etag'] = "D1EBA737938B05B5A35ECBE00E26C46D3D50AB8E00DDF4FE20D9EE61DC5DCC29E11C2239B7EDA7C148737D891423DFD9FCDB49BCFB4B9859C6E35A894090CC49"
        resp.headers['Cache-Control'] = "no-cache, private"
        return resp
