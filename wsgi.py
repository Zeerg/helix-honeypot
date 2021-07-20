from app import helix_honeypot

from gunicorn.http import wsgi

# Remove the header because the k8s api doesn't return one.
class Response(wsgi.Response):
    def default_headers(self, *args, **kwargs):
        headers = super(Response, self).default_headers(*args, **kwargs)
        return [h for h in headers if not h.startswith("Server:")]


wsgi.Response = Response

if __name__ == "__main__":
    helix_honeypot.run(host="0.0.0.0", port=8000)
