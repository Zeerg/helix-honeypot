package docker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"helix-honeypot/logger"
	"helix-honeypot/model"
)

func request(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestDockerLifecycleAndPrivacy(t *testing.T) {
	var log bytes.Buffer
	h := NewHandler(logger.NewEventLoggerWithConfig(&log, model.LoggingConfig{}, "synthetic-password"))
	created := request(h, "POST", "/v1.45/containers/create?name=test", `{"Image":"alpine:3.20","Env":["PASSWORD=synthetic-password"],"Cmd":["touch","/tmp/must-never-exist"],"HostConfig":{"Privileged":true,"Binds":["/:/host"],"NetworkMode":"host"}}`)
	if created.Code != 201 {
		t.Fatalf("create: %d %s", created.Code, created.Body)
	}
	var result struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	base := "/v1.45/containers/" + result.ID
	if w := request(h, "POST", base+"/start", ""); w.Code != 204 {
		t.Fatalf("start: %d", w.Code)
	}
	if w := request(h, "GET", base+"/json", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"Running":true`) {
		t.Fatalf("inspect: %d %s", w.Code, w.Body)
	}
	if w := request(h, "DELETE", base, ""); w.Code != 409 {
		t.Fatalf("running delete: %d", w.Code)
	}
	if w := request(h, "POST", base+"/stop", ""); w.Code != 204 {
		t.Fatalf("stop: %d", w.Code)
	}
	if w := request(h, "DELETE", base, ""); w.Code != 204 {
		t.Fatalf("delete: %d", w.Code)
	}
	if w := request(h, "GET", base+"/json", ""); w.Code != 404 {
		t.Fatalf("deleted inspect: %d", w.Code)
	}
	if strings.Contains(log.String(), "synthetic-password") || strings.Contains(log.String(), "/tmp/must-never-exist") || strings.Contains(log.String(), "/:/host") {
		t.Fatalf("payload leaked into telemetry: %s", &log)
	}
	if !strings.Contains(log.String(), "privileged:true") || !strings.Contains(log.String(), "host_mount_requested:true") {
		t.Fatalf("missing intent flags: %s", &log)
	}
}

func TestDockerRefusesExecutionAndReclaimsExecs(t *testing.T) {
	h := NewHandler(nil)
	w := request(h, "POST", "/containers/web/exec", `{"Cmd":["id"]}`)
	var value struct {
		ID string `json:"Id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &value)
	if w.Code != 201 || value.ID == "" {
		t.Fatalf("exec create: %d %s", w.Code, w.Body)
	}
	if w := request(h, "POST", "/exec/"+value.ID+"/start", `{"Detach":false}`); w.Code != 501 {
		t.Fatalf("execution was not refused: %d", w.Code)
	}
	if w := request(h, "DELETE", "/containers/web?force=1", ""); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if w := request(h, "GET", "/exec/"+value.ID+"/json", ""); w.Code != 404 {
		t.Fatalf("exec leaked after deletion: %d", w.Code)
	}
}

func TestDockerRequestAndStateLimits(t *testing.T) {
	h := NewHandler(nil)
	if w := request(h, "POST", "/containers/create", strings.Repeat("x", maxBody+1)); w.Code != 413 {
		t.Fatalf("oversize body: %d", w.Code)
	}
	if w := request(h, "GET", "/v1.99/info", ""); w.Code != 400 {
		t.Fatalf("future API: %d", w.Code)
	}
	if w := request(h, "POST", "/containers/create?name=../bad", `{"Image":"alpine"}`); w.Code != 400 {
		t.Fatalf("bad name: %d", w.Code)
	}
	for i := 1; i < maxContainers; i++ {
		if w := request(h, "POST", fmt.Sprintf("/containers/create?name=c%d", i), `{"Image":"alpine"}`); w.Code != 201 {
			t.Fatalf("create %d: %d", i, w.Code)
		}
	}
	if w := request(h, "POST", "/containers/create", `{"Image":"alpine"}`); w.Code != 503 {
		t.Fatalf("capacity not enforced: %d", w.Code)
	}
	if w := request(h, "DELETE", "/containers/c1", ""); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if w := request(h, "POST", "/containers/create?name=reclaimed", `{"Image":"alpine"}`); w.Code != 201 {
		t.Fatalf("capacity not reclaimed: %d", w.Code)
	}
}

func TestDockerConcurrentRequests(t *testing.T) {
	h := NewHandler(nil)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				w := request(h, "POST", fmt.Sprintf("/containers/create?name=c%d", i), `{"Image":"alpine"}`)
				if w.Code != 201 && w.Code != 409 {
					t.Errorf("create: %d", w.Code)
				}
				_ = request(h, "GET", "/containers/json?all=1", "")
				_ = request(h, "DELETE", fmt.Sprintf("/containers/c%d", i), "")
			}
		}(i)
	}
	wg.Wait()
}
