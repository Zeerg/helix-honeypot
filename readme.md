<p align="center"> 
  <img src="images/cover.png" width="650" title="Helix" align="center">
</p>

---

[![Docker Image CI](https://github.com/Zeerg/helix-honeypot/actions/workflows/docker-image.yml/badge.svg)](https://github.com/Zeerg/helix-honeypot/actions/workflows/docker-image.yml)

# Helix Honeypot

Helix is a flexible honeypot designed to mimic Kubernetes API server behavior and serve as an active defense mechanism. It provides an effective way to detect malicious activities targeting Kubernetes infrastructure without running a full implementation.

## Features

- **Kubernetes API Emulation**: Helix runs in two modes: API mode and Active Defense (AD) mode. In API mode, it emulates a typical Kubernetes API server, responding to various API endpoints as expected. In AD mode, it generates never-ending responses to disrupt and confuse network crawlers.
- **Randomness Generation**: Helix can generate random pods, namespaces, ingress, and secrets.
- **Logging and Analysis**: Helix logs all requests and can store them in a MongoDB database for further analysis and monitoring.
- **Flexible Configuration**: Helix can be configured using environment variables or a TOML configuration file, allowing for easy customization and deployment.

## Usage

To use Helix, follow these steps:

1. Clone this repository.
2. Configure the environment variables or the TOML configuration file according to your requirements (see "Configuration" section below).
3. Run Helix using Docker or directly on your machine.

## Configuration

The behavior of Helix honeypot can be adjusted through environment variables or a TOML configuration file.

### Environment Variables

- `K8SAPI_VERSION` (default: `"v1.19"`): Specifies the Kubernetes API version that Helix emulates.
- `IP_BASE` (default: `"192.168"`): Defines the base IP address for generated resources.
- `GENERATE_KUBE_SYSTEM` (default: `true`): Enables or disables the generation of Kube system configuration.
- `GENERATE_RANDOMNESS` (default: `true`): Enables or disables the generation of random pods, namespaces, ingress, and secrets.

### TOML Configuration

You can also provide a TOML configuration file (`config.toml`) with the following structure:

```toml
[HTTP]
Host = "localhost"
Port = "80"

[Kubernetes]
APIVersion = "v1.19"
IPBase = "192.168"
GenerateKubeSystem = true
GenerateRandomness = true

[MongoDB]
Username = "helix"
Password = ""
Host = ""
Database = "honeypot-data"
Collection = "k8s-data"
URI = ""
LogToMongoDB = false

[RunMode]
Mode = "api"
```
### Local Testing
To test Helix locally, follow these steps:

Clone this repository.
Run docker-compose up -d to start Helix as a Docker container.

### Deployment

You can deploy Helix using Docker by running the following command:
docker run -d -p 80:80 helixhoneypot/helixhoneypot