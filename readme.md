<p align="center"> 
  <img src="images/cover.png" width="650" title="Helix" align="center">
</p>

---

[![Docker Image CI](https://github.com/Zeerg/helix-honeypot/actions/workflows/docker-image.yml/badge.svg)](https://github.com/Zeerg/helix-honeypot/actions/workflows/docker-image.yml)

# Helix Honeypot

Helix is a versatile honeypot designed to mimic the behavior of various protocols including Kubernetes API server, HTTP, TCP, and UDP, serving as an active defense mechanism. Its primary goal is to detect malicious activities targeting infrastructure across different protocols without running a full-scale implementation. Helix provides the flexibility of deploying a customized honeypot that meets the specific requirements of your environment, thereby enhancing your ability to detect and mitigate threats.

## Features

- **Multi-Protocol Emulation**: Helix emulates the behavior of various protocols including Kubernetes API server, HTTP, TCP, and UDP. It can run in either API mode, providing expected responses to various API endpoints, or in Active Defense (AD) mode, generating never-ending responses to disrupt and confuse network crawlers.
- **Kubernetes API Emulation**: In Kubernetes mode, Helix mimics a Kubernetes API server, providing responses to various API endpoints and generating random Kubernetes resources such as pods, namespaces, ingress, and secrets.
- **HTTP, TCP, and UDP Emulation**: Helix can also run as a simple HTTP, TCP, or UDP server, providing basic responses to requests and serving as a general-purpose honeypot for these protocols.
- **Logging and Analysis**: Helix logs all requests across all supported protocols. It can store these logs in a MongoDB database for further analysis and monitoring, providing insights into attempted attacks and helping to identify patterns and trends.
- **Randomness Generation**: In Kubernetes mode, Helix has the ability to generate random Kubernetes resources, adding to the realism of the honeypot and helping to deceive attackers.
- **Flexible Configuration**: Helix can be configured using environment variables or a TOML configuration file. This allows for easy customization of the honeypot's behavior and deployment in a variety of environments.


## Usage

To use Helix, follow these steps:

1. Clone this repository.
2. Configure the environment variables or the TOML configuration file according to your requirements (see "Configuration" section below).
3. Run Helix using Docker or directly on your machine.

## Configuration

The behavior of Helix honeypot can be adjusted through environment variables or a TOML configuration file. 

Here are the configuration options:

- **runMode**: The mode in which Helix runs. Options are `"k8s"`, `"http"`, `"udp"`, `"tcp"`, `"ad"`.
- **location**: The location of the Helix server.
- **K8S**: The settings for the Kubernetes honeypot. Includes `apiVersion`, `ipBase`, `generateKubeSys`, `generateRand`, `host`, `port`, `tokenValues`, and `tokenNames`.
- **HTTP**: The settings for the HTTP honeypot. Includes `host` and `port`.
- **UDP**: The settings for the UDP honeypot. Includes `host` and `port`.
- **TCP**: The settings for the TCP honeypot. Includes `host` and `port`.
- **MongoDB**: The settings for MongoDB logging. Includes `username`, `password`, `host`, `database`, `collection`, `uri`, and `logToMongoDB`.

### TOML Configuration

You can also provide a TOML configuration file (`config.toml`) with the following structure:

```toml
runMode = "k8s"
location = "your_location"

[K8S]
apiVersion = "v1.19"
ipBase = "192.168"
generateKubeSys = true
generateRand = true
host = "localhost"
port = "8111"
tokenValues = ["2fh2phf", "2oijfoiesnf", "i2efhiouwefbuisb"]
tokenNames = ["test1", "test23", "test4"]

[HTTP]
host = "localhost"
port = "80"

[UDP]
host = "localhost"
port = "53"

[TCP]
host = "localhost"
port = "3000"

[MongoDB]
username = "helix"
password = ""
host = ""
database = "honeypot-data"
collection = "k8s-data"
uri = ""
logToMongoDB = false
```

### Local Testing
To test Helix locally, follow these steps:

Clone this repository.
Run docker-compose up -d to start Helix as a Docker container.

### Deployment

You can deploy Helix using Docker by running the following command:
docker run -d -p 80:80 helixhoneypot/helixhoneypot