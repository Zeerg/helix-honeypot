<p align="center"> 
  <img src="images/cover.png" width=650" title="helix" align="center">
</p>

---
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