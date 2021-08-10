<p align="center"> 
  <img src="images/cover.png" width=650" title="helix" align="center">
</p>

---
# Introduction
Helix is a honeypot that fakes the K8s API server
# Local Testing
Clone this repo
```
go run main.go
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