<p align="center"> 
  <img src="images/cover.png" width=650" title="helix" align="center">
</p>

---
[![Docker Image CI](https://github.com/Zeerg/helix-honeypot/actions/workflows/docker-image.yml/badge.svg)](https://github.com/Zeerg/helix-honeypot/actions/workflows/docker-image.yml)

# Introduction
Helix is a honeypot that serves two primary purposes. When running in K8s mode it listens and responds as a typical K8s api server(most endpoints). When running in active defense mode the api responses become massive and are meant to disrupt typical internet scanners.

# Usage
```
Usage:
  -mode string
    	The run mode for the honeypot [api, ad] (default "api")
```

# Local Testing
Clone this repo
```
docker-compose up -d
```
Setup your kubeconfig for helix
```
- cluster:
    server: http://127.0.0.1:8000
  name: helix
- context:
    cluster: helix
    user: helix
  name: helix
- name: helix
  user: {}
```
# Deployment
* Dockerhub
```
docker run -d -p80:8000 helixhoneypot/helixhoneypot
```
* Logging

For now all logging is done to stdout so if running inside docker you can add a driver to grab them. 
