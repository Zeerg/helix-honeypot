// Package kubelet emulates a misconfigured kubelet read-only API surface.
// It serves bounded node workload metadata and records every interaction;
// streaming endpoints (exec, attach, portforward, run) are always refused.
package kubelet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"

	"helix-honeypot/internal/netlimit"
	"helix-honeypot/logger"
	"helix-honeypot/model"
)

const (
	shutdownTimeout    = 5 * time.Second
	maxHTTPConnections = 128
	maxHTTPBodyBytes   = 64 << 10
)

// StartKubeletHoneypot serves a kubelet-shaped HTTP surface until ctx is
// cancelled. It never talks to a real node or container runtime.
func StartKubeletHoneypot(ctx context.Context, cfg *model.Config) error {
	if cfg == nil {
		return errors.New("kubelet honeypot requires configuration")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	e := newRouter(cfg)
	events, err := logger.NewEventLoggerFromConfig(nil, cfg)
	if err != nil {
		return fmt.Errorf("configure event sinks: %w", err)
	}
	defer events.Close()
	e.Use(limitRequestBody)
	e.Use(events.HTTPMiddleware("kubelet"))

	addr := net.JoinHostPort(cfg.Kubelet.Host, cfg.Kubelet.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen kubelet honeypot: %w", err)
	}
	cappedListener, err := netlimit.NewCappedListener(listener, maxHTTPConnections)
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("cap kubelet honeypot listener: %w", err)
	}
	defer cappedListener.Close()

	start := echo.StartConfig{
		Address:         addr,
		Listener:        cappedListener,
		HideBanner:      true,
		HidePort:        true,
		GracefulTimeout: shutdownTimeout,
		BeforeServeFunc: func(server *http.Server) error {
			server.ReadHeaderTimeout = 5 * time.Second
			server.ReadTimeout = 5 * time.Second
			server.WriteTimeout = 10 * time.Second
			server.IdleTimeout = 60 * time.Second
			server.MaxHeaderBytes = 16 * 1024
			return nil
		},
	}
	if err := start.Start(ctx, e); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve kubelet honeypot: %w", err)
	}
	return nil
}

func newRouter(cfg *model.Config) *echo.Echo {
	node := &nodeView{cfg: cfg, startedAt: time.Now().UTC()}

	e := echo.NewWithConfig(echo.Config{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		HTTPErrorHandler: func(c *echo.Context, err error) {
			response, unwrapErr := echo.UnwrapResponse(c.Response())
			if unwrapErr == nil && response.Committed {
				return
			}
			status := echo.StatusCode(err)
			if status < http.StatusBadRequest || status > 599 {
				status = http.StatusInternalServerError
			}
			_ = c.NoContent(status)
		},
	})
	e.GET("/healthz", node.healthz)
	e.GET("/pods", node.pods)
	e.GET("/runningpods", node.pods)
	e.GET("/metrics", node.metrics)
	e.GET("/metrics/cadvisor", node.cadvisorMetrics)
	e.GET("/stats/summary", node.statsSummary)
	e.GET("/configz", node.configz)
	e.GET("/logs/", node.logIndex)
	e.GET("/containerLogs/*", node.containerLogs)
	for _, path := range []string{"/exec/*", "/attach/*", "/portforward/*", "/run/*", "/cri/*"} {
		e.Any(path, node.streamingRefused)
	}
	e.Any("/*", func(c *echo.Context) error {
		return c.NoContent(http.StatusNotFound)
	})
	return e
}

// nodeView renders the fixed, synthetic view of the node workload. All values
// are derived from configuration or constants; nothing is read from a host.
type nodeView struct {
	cfg       *model.Config
	startedAt time.Time
}

func (n *nodeView) healthz(c *echo.Context) error {
	if c.QueryParam("verbose") != "" {
		return c.String(http.StatusOK, "[+]ping ok\n[+]log ok\n[+]syncloop ok\nhealthz check passed\n")
	}
	return c.String(http.StatusOK, "ok")
}

func (n *nodeView) pods(c *echo.Context) error {
	return c.JSON(http.StatusOK, map[string]any{
		"kind":       "PodList",
		"apiVersion": "v1",
		"metadata":   map[string]any{},
		"items":      n.nodePods(),
	})
}

func (n *nodeView) metrics(c *echo.Context) error {
	body := "# HELP kubelet_running_pods Number of pods currently running\n" +
		"# TYPE kubelet_running_pods gauge\n" +
		fmt.Sprintf("kubelet_running_pods %d\n", len(n.nodePods())) +
		"# HELP kubelet_running_containers Number of containers currently running\n" +
		"# TYPE kubelet_running_containers gauge\n" +
		fmt.Sprintf("kubelet_running_containers %d\n", len(n.nodePods())) +
		"# HELP kubelet_node_name The node's name\n" +
		"# TYPE kubelet_node_name gauge\n" +
		fmt.Sprintf("kubelet_node_name{node_name=%q} 1\n", n.nodeName())
	return c.String(http.StatusOK, body)
}

func (n *nodeView) cadvisorMetrics(c *echo.Context) error {
	var body strings.Builder
	body.WriteString("# HELP container_cpu_usage_seconds_total Cumulative cpu time consumed\n" +
		"# TYPE container_cpu_usage_seconds_total counter\n")
	for i, pod := range n.nodePods() {
		meta, _ := pod["metadata"].(map[string]any)
		body.WriteString(fmt.Sprintf("container_cpu_usage_seconds_total{namespace=%q,pod=%q,container=%q} %.2f\n",
			meta["namespace"], meta["name"], "main", float64(40+i*17)+0.37))
	}
	return c.String(http.StatusOK, body.String())
}

func (n *nodeView) statsSummary(c *echo.Context) error {
	node := map[string]any{
		"nodeName":         n.nodeName(),
		"systemContainers": []any{},
		"startTime":        n.startedAt.Format(time.RFC3339),
		"cpu":              map[string]any{"usageNanoCores": 184_000_000, "usageCoreNanoSeconds": 12_840_000_000_000},
		"memory":           map[string]any{"workingSetBytes": 1_834_000_000, "availableBytes": 14_400_000_000},
		"fs":               map[string]any{"capacityBytes": 250_000_000_000, "usedBytes": 38_400_000_000, "availableBytes": 211_600_000_000},
		"runtime":          map[string]any{"imageFs": map[string]any{"capacityBytes": 250_000_000_000, "usedBytes": 12_300_000_000}},
	}
	pods := make([]any, 0, len(n.nodePods()))
	for i, pod := range n.nodePods() {
		meta, _ := pod["metadata"].(map[string]any)
		pods = append(pods, map[string]any{
			"podRef": map[string]any{
				"name": meta["name"], "namespace": meta["namespace"], "uid": meta["uid"],
			},
			"startTime": n.startedAt.Format(time.RFC3339),
			"cpu":       map[string]any{"usageNanoCores": 12_000_000 + i*3_700_000},
			"memory":    map[string]any{"workingSetBytes": 84_000_000 + i*19_000_000},
		})
	}
	return c.JSON(http.StatusOK, map[string]any{"node": node, "pods": pods})
}

func (n *nodeView) configz(c *echo.Context) error {
	return c.JSON(http.StatusOK, map[string]any{
		"kubeletconfig": map[string]any{
			"kind":         "KubeletConfiguration",
			"apiVersion":   "kubelet.config.k8s.io/v1beta1",
			"address":      "0.0.0.0",
			"port":         10250,
			"readOnlyPort": 0,
			"authentication": map[string]any{
				"anonymous": map[string]any{"enabled": true},
				"webhook":   map[string]any{"enabled": false},
			},
			"authorization":            map[string]any{"mode": "AlwaysAllow"},
			"clusterDomain":            "cluster.local",
			"clusterDNS":               []string{"10.43.0.10"},
			"cgroupDriver":             "systemd",
			"containerRuntimeEndpoint": "unix:///run/containerd/containerd.sock",
		},
	})
}

func (n *nodeView) logIndex(c *echo.Context) error {
	// Real kubelets render an HTML directory listing of host log paths.
	var body strings.Builder
	body.WriteString("<html>\n<head><title>/var/log/</title></head>\n<body>\n<h1>/var/log/</h1><pre>")
	for _, entry := range []string{"containers/", "pods/", "kubelet.log", "syslog", "auth.log", "kern.log"} {
		body.WriteString(fmt.Sprintf("<a href=%q>%s</a>\n", entry, entry))
	}
	body.WriteString("</pre>\n</body>\n</html>\n")
	return c.HTML(http.StatusOK, body.String())
}

func (n *nodeView) containerLogs(c *echo.Context) error {
	// Path shape: /containerLogs/<namespace>/<pod>/<container>
	parts := strings.Split(strings.TrimPrefix(c.Param("*"), "/"), "/")
	if len(parts) != 3 {
		return c.NoContent(http.StatusNotFound)
	}
	namespace, pod, container := parts[0], parts[1], parts[2]
	if !n.podExists(namespace, pod) {
		return c.String(http.StatusNotFound, fmt.Sprintf("pod %q does not exist in namespace %q\n", pod, namespace))
	}
	lines := fmt.Sprintf("%s I0923 12:04:01.033102       1 main.go:42] service started\n"+
		"%s I0923 12:04:01.211588       1 server.go:119] listening on :8080\n"+
		"%s I0923 12:04:11.904211       1 server.go:201] handled request status=200\n",
		n.startedAt.Format(time.RFC3339), n.startedAt.Format(time.RFC3339), n.startedAt.Format(time.RFC3339))
	_ = container
	return c.String(http.StatusOK, lines)
}

// streamingRefused answers exec/attach/portforward/run probes the way a
// kubelet answers a non-upgraded request: a bounded refusal. The attempt is
// already captured by the event middleware before we get here.
func (n *nodeView) streamingRefused(c *echo.Context) error {
	return c.String(http.StatusBadRequest, "Bad Request\n\nunable to upgrade streaming request\n")
}

func (n *nodeView) nodeName() string {
	return n.cfg.Kubelet.NodeName
}

func (n *nodeView) podExists(namespace, name string) bool {
	for _, pod := range n.nodePods() {
		meta, _ := pod["metadata"].(map[string]any)
		if meta["namespace"] == namespace && meta["name"] == name {
			return true
		}
	}
	return false
}

// nodePods is a static workload view for the configured node. DaemonSet-style
// pods live on every node; the application pods give scanners something to
// pivot toward.
func (n *nodeView) nodePods() []map[string]any {
	node := n.nodeName()
	return []map[string]any{
		n.pod("kube-proxy-2k9jv", "kube-system", "registry.k8s.io/kube-proxy:v1.37.0", node, 30),
		n.pod("metrics-server-7db5f8d5b9-5c2tx", "kube-system", "registry.k8s.io/metrics-server/metrics-server:v0.9.0", node, 31),
		n.pod("web-7f5cb9d59c-hk6qn", "default", "nginx:1.30.5", node, 40),
		n.pod("redis-0", "default", "redis:7.4", node, 41),
	}
}

func (n *nodeView) pod(name, namespace, image, node string, ipOffset int) map[string]any {
	podIP := n.podIP(ipOffset)
	uid := uidFor("kubelet/" + namespace + "/" + name)
	return map[string]any{
		"kind":       "Pod",
		"apiVersion": "v1",
		"metadata": map[string]any{
			"name":              name,
			"namespace":         namespace,
			"uid":               uid,
			"creationTimestamp": n.startedAt.Format(time.RFC3339),
		},
		"spec": map[string]any{
			"nodeName": node,
			"containers": []any{map[string]any{
				"name":  name,
				"image": image,
			}},
		},
		"status": map[string]any{
			"phase":  "Running",
			"podIP":  podIP,
			"podIPs": []any{map[string]any{"ip": podIP}},
			"hostIP": n.podIP(10),
			"containerStatuses": []any{map[string]any{
				"name":  name,
				"ready": true,
				"state": map[string]any{
					"running": map[string]any{"startedAt": n.startedAt.Format(time.RFC3339)},
				},
			}},
		},
	}
}

// podIP derives a deterministic pod address from the configured cluster IP
// base so kubelet and apiserver views agree when both modes run.
func (n *nodeView) podIP(offset int) string {
	base := strings.TrimSpace(n.cfg.K8S.IPBase)
	if base == "" {
		base = "10.42.0.0"
	}
	parts := strings.Split(base, ".")
	if len(parts) != 4 {
		return "10.42.0.9"
	}
	return fmt.Sprintf("%s.%s.2.%d", parts[0], parts[1], offset)
}

func uidFor(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	hexed := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexed[0:8], hexed[8:12], hexed[12:16], hexed[16:20], hexed[20:32])
}

func limitRequestBody(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		if c.Request().Body != nil {
			c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, maxHTTPBodyBytes)
		}
		return next(c)
	}
}
