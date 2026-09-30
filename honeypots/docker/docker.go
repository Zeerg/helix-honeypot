// Package docker emulates an anonymous Docker Engine API without a daemon,
// socket, image pulls, subprocesses, or any host filesystem operations.
package docker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"helix-honeypot/internal/netlimit"
	"helix-honeypot/logger"
	"helix-honeypot/model"
)

const (
	engineVersion = "26.1.4"
	apiVersion    = "1.45"
	maxBody       = 64 << 10
	maxContainers = 128
	maxStoreBytes = 8 << 20
	maxExecs      = 128
)

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

type containerConfig struct {
	Image      string
	Cmd        []string
	Env        []string
	Labels     map[string]string
	HostConfig struct {
		Privileged  bool
		Binds       []string
		NetworkMode string
	}
}

type container struct {
	ID, Name, State string
	Created         int64
	Config          containerConfig
	Size            int
}

type sensor struct {
	mu         sync.Mutex
	containers map[string]*container
	execs      map[string]string
	bytes      int
	events     *logger.EventLogger
}

// NewHandler returns an independent, bounded simulated Docker host.
func NewHandler(events *logger.EventLogger) http.Handler {
	s := &sensor{containers: make(map[string]*container), execs: make(map[string]string), events: events}
	s.containers[strings.Repeat("a", 64)] = &container{ID: strings.Repeat("a", 64), Name: "web", State: "running", Created: time.Now().Add(-time.Hour).Unix(), Config: containerConfig{Image: "alpine:3.20", Cmd: []string{"sleep", "3600"}}}
	return s
}

func StartDockerHoneypot(ctx context.Context, cfg *model.Config) error {
	if ctx == nil || cfg == nil {
		return errors.New("Docker sensor requires context and configuration")
	}
	events, err := logger.NewEventLoggerFromConfig(nil, cfg)
	if err != nil {
		return err
	}
	defer events.Close()
	listener, err := net.Listen("tcp", net.JoinHostPort(cfg.Docker.Host, cfg.Docker.Port))
	if err != nil {
		return err
	}
	capped, err := netlimit.NewCappedListener(listener, 64)
	if err != nil {
		listener.Close()
		return err
	}
	defer capped.Close()
	server := &http.Server{Handler: NewHandler(events), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
			_ = server.Close()
		case <-finished:
		}
	}()
	err = server.Serve(capped)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

type reply struct {
	code                            int
	data                            []byte
	action, outcome, target, detail string
}

func jsonReply(code int, value any) reply {
	data, err := json.Marshal(value)
	if err != nil {
		return reply{code: 500, data: []byte(`{"message":"response unavailable"}`)}
	}
	return reply{code: code, data: data}
}
func errorReply(code int, message string) reply {
	return jsonReply(code, map[string]string{"message": message})
}

func (s *sensor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("API-Version", apiVersion)
	w.Header().Set("Docker-Experimental", "false")
	w.Header().Set("OSType", "linux")
	w.Header().Set("Server", "Docker/"+engineVersion+" (linux)")
	result := s.handle(w, r)
	w.Header().Set("Content-Type", "application/json")
	if result.action == "ping" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.WriteHeader(result.code)
	n := 0
	if r.Method != http.MethodHead && result.code != http.StatusNoContent {
		n, _ = w.Write(result.data)
	}
	if s.events != nil {
		outcome := result.outcome
		if outcome == "" {
			outcome = "simulated"
			if result.code >= 400 {
				outcome = "rejected"
			}
		}
		s.events.Write(model.Event{Sensor: "docker", Method: r.Method, Path: r.URL.Path, RemoteAddr: r.RemoteAddr, StatusCode: result.code, BytesSent: int64(n), Action: result.action, Outcome: outcome, Profile: "docker/" + engineVersion, Target: result.target, Detail: result.detail})
	}
}

func (s *sensor) handle(w http.ResponseWriter, r *http.Request) reply {
	if len(r.URL.Path) > 4096 || len(r.URL.RawQuery) > 8192 {
		return errorReply(414, "request target too long")
	}
	path := r.URL.Path
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > 0 && strings.HasPrefix(parts[0], "v1.") {
		minor, err := strconv.Atoi(strings.TrimPrefix(parts[0], "v1."))
		if err != nil || minor < 24 || minor > 45 || parts[0] != fmt.Sprintf("v1.%d", minor) {
			return errorReply(400, "unsupported client API version")
		}
		path = "/" + strings.Join(parts[1:], "/")
	}
	var config containerConfig
	var size int
	if r.Method == http.MethodPost && (path == "/containers/create" || strings.HasSuffix(path, "/exec")) {
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			return errorReply(413, "request body too large")
		}
		size = len(data)
		if err = json.Unmarshal(data, &config); err != nil {
			return errorReply(400, "invalid JSON object")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var result reply
	switch {
	case path == "/_ping" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		return reply{code: 200, data: []byte("OK"), action: "ping"}
	case path == "/version" && r.Method == http.MethodGet:
		result = jsonReply(200, map[string]any{"Version": engineVersion, "ApiVersion": apiVersion, "MinAPIVersion": "1.24", "GitCommit": "de5c9cf", "GoVersion": "go1.21.9", "Os": "linux", "Arch": "amd64", "KernelVersion": "6.8.0", "BuildTime": "2024-06-05T11:29:20Z", "Components": []any{map[string]any{"Name": "Engine", "Version": engineVersion, "Details": map[string]string{"ApiVersion": apiVersion, "MinAPIVersion": "1.24", "Os": "linux", "Arch": "amd64"}}}})
		result.action = "version"
	case path == "/info" && r.Method == http.MethodGet:
		running := 0
		for _, c := range s.containers {
			if c.State == "running" {
				running++
			}
		}
		result = jsonReply(200, map[string]any{"ID": strings.Repeat("b", 64), "Name": "worker-01", "ServerVersion": engineVersion, "Containers": len(s.containers), "ContainersRunning": running, "ContainersStopped": len(s.containers) - running, "ContainersPaused": 0, "Images": 1, "Driver": "overlay2", "DriverStatus": [][]string{}, "Plugins": map[string]any{"Volume": []string{"local"}, "Network": []string{"bridge", "host", "null"}, "Log": []string{"json-file"}}, "NCPU": 4, "MemTotal": 8 << 30, "DockerRootDir": "/var/lib/docker", "OSType": "linux", "Architecture": "x86_64", "OperatingSystem": "Ubuntu 22.04.4 LTS", "KernelVersion": "6.8.0", "LoggingDriver": "json-file", "CgroupDriver": "systemd", "CgroupVersion": "2", "DefaultRuntime": "runc", "Runtimes": map[string]any{"runc": map[string]string{"path": "runc"}}, "Swarm": map[string]string{"LocalNodeState": "inactive"}, "SecurityOptions": []string{"name=seccomp,profile=builtin"}, "SystemTime": time.Now().UTC().Format(time.RFC3339Nano), "Warnings": []string{}})
		result.action = "info"
	case path == "/containers/json" && r.Method == http.MethodGet:
		items := []any{}
		for _, c := range s.containers {
			if c.State != "running" && r.URL.Query().Get("all") != "1" && r.URL.Query().Get("all") != "true" {
				continue
			}
			items = append(items, map[string]any{"Id": c.ID, "Names": []string{"/" + c.Name}, "Image": c.Config.Image, "ImageID": "sha256:" + strings.Repeat("c", 64), "Command": strings.Join(c.Config.Cmd, " "), "Created": c.Created, "State": c.State, "Status": c.State, "Ports": []any{}, "Labels": c.Config.Labels, "Mounts": []any{}, "NetworkSettings": map[string]any{"Networks": map[string]any{}}})
		}
		result = jsonReply(200, items)
		result.action = "container.list"
	case path == "/images/json" && r.Method == http.MethodGet:
		result = jsonReply(200, []any{map[string]any{"Id": "sha256:" + strings.Repeat("c", 64), "RepoTags": []string{"alpine:3.20"}, "RepoDigests": []string{}, "Created": 1717586960, "Size": 7800000, "SharedSize": -1, "Containers": -1, "Labels": map[string]string{}}})
		result.action = "image.list"
	case strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/json") && r.Method == http.MethodGet:
		result = jsonReply(200, map[string]any{"Id": "sha256:" + strings.Repeat("c", 64), "RepoTags": []string{"alpine:3.20"}, "Architecture": "amd64", "Os": "linux", "Size": 7800000, "Config": map[string]any{"Cmd": []string{"/bin/sh"}}, "RootFS": map[string]any{"Type": "layers", "Layers": []string{}}})
		result.action = "image.inspect"
	case path == "/networks" && r.Method == http.MethodGet:
		result = jsonReply(200, []any{})
		result.action = "network.list"
	case path == "/volumes" && r.Method == http.MethodGet:
		result = jsonReply(200, map[string]any{"Volumes": []any{}, "Warnings": []string{}})
		result.action = "volume.list"
	case path == "/containers/create" && r.Method == http.MethodPost:
		if config.Image == "" || len(config.Image) > 256 {
			return errorReply(400, "image is required and must be bounded")
		}
		if len(s.containers) >= maxContainers || s.bytes+size > maxStoreBytes {
			return errorReply(503, "simulated container capacity reached")
		}
		id, err := randomID()
		if err != nil {
			return errorReply(500, "identifier unavailable")
		}
		name := r.URL.Query().Get("name")
		if name == "" {
			name = "container-" + id[:12]
		}
		if !namePattern.MatchString(name) {
			return errorReply(400, "invalid container name")
		}
		for _, c := range s.containers {
			if c.Name == name {
				return errorReply(409, "container name already in use")
			}
		}
		s.containers[id] = &container{ID: id, Name: name, State: "created", Created: time.Now().Unix(), Config: config, Size: size}
		s.bytes += size
		result = jsonReply(201, map[string]any{"Id": id, "Warnings": []string{}})
		result.action = "container.create"
		result.target = id
		result.detail = fmt.Sprintf("privileged:%t host_mount_requested:%t host_network_requested:%t", config.HostConfig.Privileged, len(config.HostConfig.Binds) > 0, config.HostConfig.NetworkMode == "host")
	case strings.HasPrefix(path, "/containers/"):
		parts := strings.Split(strings.TrimPrefix(path, "/containers/"), "/")
		c := s.find(parts[0])
		if c == nil {
			return errorReply(404, "no such container")
		}
		result.target = c.ID
		if len(parts) == 1 && r.Method == http.MethodDelete {
			if c.State == "running" && r.URL.Query().Get("force") != "1" && r.URL.Query().Get("force") != "true" {
				return errorReply(409, "container is running")
			}
			delete(s.containers, c.ID)
			s.bytes -= c.Size
			for id, owner := range s.execs {
				if owner == c.ID {
					delete(s.execs, id)
				}
			}
			result.code = 204
			result.action = "container.delete"
		} else if len(parts) == 2 {
			switch {
			case parts[1] == "json" && r.Method == http.MethodGet:
				result = jsonReply(200, map[string]any{"Id": c.ID, "Name": "/" + c.Name, "Created": time.Unix(c.Created, 0).UTC().Format(time.RFC3339Nano), "State": map[string]any{"Status": c.State, "Running": c.State == "running", "Paused": false, "Restarting": false, "Dead": false, "ExitCode": 0, "Pid": 0}, "Config": c.Config, "HostConfig": c.Config.HostConfig, "NetworkSettings": map[string]any{"Ports": map[string]any{}, "Networks": map[string]any{}}, "Mounts": []any{}})
				result.action = "container.inspect"
			case (parts[1] == "start" || parts[1] == "stop" || parts[1] == "restart" || parts[1] == "kill") && r.Method == http.MethodPost:
				state := "running"
				if parts[1] == "stop" || parts[1] == "kill" {
					state = "exited"
				}
				result.code = 204
				if c.State == state && parts[1] != "restart" {
					result.code = 304
				}
				c.State = state
				result.action = "container." + parts[1]
			case parts[1] == "exec" && r.Method == http.MethodPost:
				if c.State != "running" {
					return errorReply(409, "container is not running")
				}
				if len(s.execs) >= maxExecs {
					return errorReply(503, "simulated exec capacity reached")
				}
				id, err := randomID()
				if err != nil {
					return errorReply(500, "identifier unavailable")
				}
				s.execs[id] = c.ID
				result = jsonReply(201, map[string]string{"Id": id})
				result.action = "exec.create"
			default:
				return errorReply(404, "endpoint unavailable")
			}
			result.target = c.ID
		} else {
			return errorReply(404, "endpoint unavailable")
		}
	case strings.HasPrefix(path, "/exec/"):
		parts := strings.Split(strings.TrimPrefix(path, "/exec/"), "/")
		if len(parts) != 2 {
			return errorReply(404, "endpoint unavailable")
		}
		owner, ok := s.execs[parts[0]]
		if !ok {
			return errorReply(404, "no such exec instance")
		}
		if parts[1] == "start" && r.Method == http.MethodPost {
			result = errorReply(501, "streaming execution is unavailable")
			result.action = "exec.start"
			result.outcome = "refused"
		} else if parts[1] == "json" && r.Method == http.MethodGet {
			result = jsonReply(200, map[string]any{"ID": parts[0], "ContainerID": owner, "Running": false, "ExitCode": 126, "Pid": 0})
			result.action = "exec.inspect"
		} else {
			return errorReply(404, "endpoint unavailable")
		}
		result.target = owner
	default:
		return errorReply(404, "endpoint unavailable")
	}
	return result
}

func (s *sensor) find(name string) *container {
	if c := s.containers[name]; c != nil {
		return c
	}
	var match *container
	for id, c := range s.containers {
		if c.Name == name || (len(name) >= 12 && strings.HasPrefix(id, name)) {
			if match != nil {
				return nil
			}
			match = c
		}
	}
	return match
}

func randomID() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}
