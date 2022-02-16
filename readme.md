<p align="center"> 
  <img src="images/cover.png" width=650" title="helix" align="center">
</p>

---
[![Docker Image CI](https://github.com/Zeerg/helix-honeypot/actions/workflows/docker-image.yml/badge.svg)](https://github.com/Zeerg/helix-honeypot/actions/workflows/docker-image.yml)

# Introduction
Helix is a honeypot that serves two primary purposes. When running in K8s mode it listens and responds as a typical K8s api server(most endpoints). When running in active defense a never ending response is generated on all api endpoints. 

# Run Modes
```
* api - Mocks a basic K8s API Server
* ad - Active Defense mode returns never ending stream of data on all endpoints
* kubelet - Acts like a host running an exposed kubelet server
```
# Usage
```
Usage:
  -mode string
    	The run mode for the honeypot [api, ad, kubelet] (default "api")
```

# Local Testing
Clone this repo
```
docker-compose up -d
```
Setup your kubeconfig for helix 
```
- cluster:
    server: http://127.0.0.1:80
  name: helix
- context:
    cluster: helix
    user: helix
  name: helix
- name: helix
  user: {}
```
# Deployment
* Basic Deployment Dockerhub
```
docker run -d -p80:8000 helixhoneypot/helixhoneypot
```
# Compose Examples
```
version: '3.7'

services:
  helix-honeypot-ad:
   build: helixhoneypot/helixhoneypot
   ports:
     - "8000:8000"
   entrypoint: [/helix-honeypot, -mode=ad]
   volumes:
     - /dev/urandom:/dev/urandom
  helix-honeypot:
    build: helixhoneypot/helixhoneypot
    ports:
      - "80:8000"
  helix-honeypot-kubelet:
    build: helixhoneypot/helixhoneypot
    ports:
      - "10250:8000"
  

```
# Logging

For now all logging is done to stdout so if running inside docker you can add a driver to grab them. 
