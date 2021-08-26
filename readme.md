<p align="center"> 
  <img src="images/cover.png" width=650" title="helix" align="center">
</p>

---
[![Docker Image CI](https://github.com/Zeerg/helix-honeypot/actions/workflows/docker-image.yml/badge.svg)](https://github.com/Zeerg/helix-honeypot/actions/workflows/docker-image.yml)

# Introduction
Helix is a honeypot that fakes the K8s API server. All events are logged to stdout 

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
