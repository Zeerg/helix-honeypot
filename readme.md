<p align="center"> 
  <img src="images/cover.png" width=650" title="helix" align="center">
</p>

---
[![Docker Image CI](https://github.com/Zeerg/helix-honeypot/actions/workflows/docker-image.yml/badge.svg)](https://github.com/Zeerg/helix-honeypot/actions/workflows/docker-image.yml)

# Introduction
Helix is a honeypot that serves two primary purposes. When running in K8s mode, it listens and responds as a typical K8s API server (for most endpoints). In active defense mode, a never-ending response is generated on all API endpoints. 


# Usage
```
Usage:
  -mode string
    	The run mode for the honeypot [api, ad] (default "api")
```
# Configuration

The behavior of Helix honeypot can be adjusted via environment variables:

## API 

- `K8SAPI_VERSION` (default: `"v1.19"`): Defines the Kubernetes API version.
- `IP_BASE` (default: `"192.168"`): Defines the base for generated IP addresses.
- `GENERATE_KUBE_SYSTEM` (default: `true`): If true, a Kube system configuration will be generated.
- `GENERATE_RANDOMNESS` (default: `true`): If true, the system will generate random pods, namespaces, ingress, and secrets.

# Local Testing
Clone this repo
```
docker-compose up -d
```

Setup your kubeconfig for helix example:

```
apiVersion: v1
clusters:
- cluster:
    server: http://127.0.0.1:8111
  name: helix
contexts:
- context:
    cluster: helix
    user: helix
  name: helix
current-context: helix
kind: Config
preferences: {}
users:
- name: helix
  user:
    username: helix
```
# Deployment

* Dockerhub
```
docker run -d -p80:80 helixhoneypot/helixhoneypot
```

# Logging

For now all logging is done to stdout so if running inside docker you can add a driver to grab them. 
