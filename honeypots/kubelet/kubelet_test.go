package kubelet

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"helix-honeypot/config"
)

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg := config.Defaults()
	return httptest.NewServer(newRouter(&cfg))
}

func TestKubeletHealthz(t *testing.T) {
	server := testServer(t)
	defer server.Close()

	response, err := http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("healthz = %d %q, want 200 ok", response.StatusCode, body)
	}
}

func TestKubeletPodsServeNodeWorkload(t *testing.T) {
	server := testServer(t)
	defer server.Close()

	response, err := http.Get(server.URL + "/pods")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var list struct {
		Kind  string `json:"kind"`
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				NodeName string `json:"nodeName"`
			} `json:"spec"`
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.NewDecoder(response.Body).Decode(&list); err != nil {
		t.Fatalf("decode /pods: %v", err)
	}
	if list.Kind != "PodList" || len(list.Items) == 0 {
		t.Fatalf("/pods = %#v, want a non-empty PodList", list)
	}
	for _, item := range list.Items {
		if item.Spec.NodeName != "worker-01" || item.Status.Phase != "Running" || item.Metadata.Name == "" {
			t.Fatalf("pod = %#v, unexpected shape", item)
		}
	}
}

func TestKubeletStreamingEndpointsAreRefused(t *testing.T) {
	server := testServer(t)
	defer server.Close()

	for _, path := range []string{
		"/exec/default/web-7f5cb9d59c-hk6qn/web?command=cat&command=/etc/passwd",
		"/attach/default/web-7f5cb9d59c-hk6qn/web",
		"/portforward/default/web-7f5cb9d59c-hk6qn?ports=8080",
		"/run/default/web-7f5cb9d59c-hk6qn/web",
	} {
		response, err := http.Post(server.URL+path, "text/plain", nil)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("POST %s = %d, want 400 upgrade refusal", path, response.StatusCode)
		}
	}
}

func TestKubeletContainerLogsAndUnknownPaths(t *testing.T) {
	server := testServer(t)
	defer server.Close()

	response, err := http.Get(server.URL + "/containerLogs/default/web-7f5cb9d59c-hk6qn/web")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "listening") {
		t.Fatalf("containerLogs = %d %q, want plausible log output", response.StatusCode, body)
	}

	response, err = http.Get(server.URL + "/containerLogs/default/no-such-pod/web")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("missing pod containerLogs = %d, want 404", response.StatusCode)
	}

	response, err = http.Get(server.URL + "/definitely-not-real")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown path = %d, want 404", response.StatusCode)
	}
}
