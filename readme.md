# Helix Honeypot

<p align="center"> 
  <img src="images/cover.png" width="650" title="Helix" align="center">
</p>

---

[![Docker Image CI](https://github.com/Zeerg/helix-honeypot/actions/workflows/docker-image.yml/badge.svg)](https://github.com/Zeerg/helix-honeypot/actions/workflows/docker-image.yml)

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

Here are the configuration options that Helix provides:

- **runMode**: This option allows you to set the mode in which Helix runs. Options are as follows:

  - `"k8s"`: In this mode, Helix mimics a Kubernetes environment, including API responses. This mode is useful for detecting and studying attacks that target Kubernetes clusters. 

  - `"http"`: In this mode, Helix operates as an HTTP server and responds to incoming HTTP requests. This mode can be used to attract and study various types of HTTP-based attacks, including web scraping, SQL injections, and Cross-Site Scripting (XSS).

  - `"udp"`: In this mode, Helix acts as a UDP server, listening for and responding to incoming UDP packets. This mode can be useful for detecting UDP-based attacks such as UDP flood attacks.

  - `"tcp"`: In this mode, Helix acts as a TCP server, listening for and responding to incoming TCP connections. This mode can be useful for detecting TCP-based attacks such as TCP SYN flood attacks.

  - `"def"`: This is active defense mode. It randomly selects between streaming random data back or an infinite redirect.

- **location**: This option allows you to specify the location of the Helix server as a string. This could be a physical location, a virtual location, or a network location, depending on your setup and requirements.

- **K8S**: This set of options allows you to configure the settings for the Kubernetes honeypot. These settings include the following:

  - `apiVersion`: This option allows you to specify the API version that the Kubernetes honeypot should mimic.
  
  - `ipBase`: This option allows you to specify the base IP address for the Kubernetes honeypot.
  
  - `generateKubeSys`: This option allows you to control whether or not the Kubernetes honeypot should generate Kubernetes system namespaces.
  
  - `generateRand`: This option allows you to control whether or not the Kubernetes honeypot should generate random resources.
  
  - `host`: This option allows you to specify the host for the Kubernetes honeypot.
  
  - `port`: This option allows you to specify the port for the Kubernetes honeypot.
  
  - `tokenValues`: This option allows you to specify the honeytoken values for the Kubernetes honeypot.
  
  - `tokenNames`: This option allows you to specify the honeytoken names for the Kubernetes honeypot.

- **HTTP**: This set of options allows you to configure the settings for the HTTP honeypot. These settings include the following:

  - `host`: This option allows you to specify the host for the HTTP honeypot.
  
  - `port`: This option allows you to specify the port for the HTTP honeypot.

- **UDP**: This set of options allows you to configure the settings for the UDP honeypot. These settings include the following:

  - `host`: This option allows you to specify the host for the UDP honeypot.
  
  - `port`: This option allows you to specify the port for the UDP honeypot.

- **TCP**: This set of options allows you to configure the settings for the TCP honeypot. These settings include the following:

  - `host`: This option allows you to specify the host for the TCP honeypot.
  
  - `port`: This option allows you to specify the port for the TCP honeypot.

- **MongoDB**: This set of options allows you to configure the settings for MongoDB logging. These settings include the following:

  - `username`: This option allows you to specify the username for MongoDB.
  
  - `password`: This option allows you to specify the password for MongoDB.
  
  - `host`: This option allows you to specify the host for MongoDB.
  
  - `database`: This option allows you to specify the database for MongoDB.
  
  - `collection`: This option allows you to specify the collection for MongoDB.
  
  - `uri`: This option allows you to specify the URI for MongoDB.
  
  - `logToMongoDB`: This option allows you to control whether or not Helix should log events to MongoDB.

Please refer to the example configuration files provided in the repository for further details on how to set these options.

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

```
version: '3.7'

services:
  helix-honeypot-k8s:
    build: ./
    ports:
      - "8111:8111"
    environment:
      - RUN_MODE=k8s
      - HELIX_LOCATION=testing
      - K8SAPI_VERSION=v1.21
      - IP_BASE=192.168
      - GENERATE_KUBE_SYSTEM=true
      - GENERATE_RANDOMNESS=true
      - K8S_HOST=0.0.0.0
      - K8S_PORT=8111

  helix-honeypot-http:
    build: ./
    ports:
      - "8000:8000"
    environment:
      - RUN_MODE=http
      - HELIX_HTTP_HOST=0.0.0.0
      - HELIX_HTTP_PORT=8000

  helix-honeypot-tcp:
    build: ./
    ports:
      - "3000:3000"
    environment:
      - RUN_MODE=tcp
      - HELIX_TCP_HOST=0.0.0.0
      - HELIX_TCP_PORT=3000

  helix-honeypot-udp:
    build: ./
    ports:
      - "53:53/udp"
    environment:
      - RUN_MODE=udp
      - HELIX_UDP_HOST=0.0.0.0
      - HELIX_UDP_PORT=53

  helix-honeypot-def:
    build: ./
    ports:
      - "8001:8001"
    environment:
      - RUN_MODE=def
      - HELIX_DEF_HOST=0.0.0.0
      - HELIX_DEF_PORT=8001

```