// Warden Lab microservice — Go (net/http from the standard library).
// One static binary, built at apply time. Same contract as every service.
package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var root = env("LAB_ROOT", "/tmp")
var strip = regexp.MustCompile(`^/svc/[^/]+`)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func item(id string) string {
	// interpolated on purpose (SQLi target); sqlite3 invoked read-only
	out, err := exec.Command("/usr/bin/sqlite3", "-readonly", filepath.Join(root, "data", "items.sqlite"),
		fmt.Sprintf("SELECT id||'|'||name||'|'||note FROM items WHERE id = %s", id)).Output()
	if err != nil {
		return "error"
	}
	if len(out) == 0 {
		return "no result"
	}
	return string(out)
}

func main() {
	port := env("PORT", "3104")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Lab-Service", "go")
		p := strip.ReplaceAllString(r.URL.Path, "")
		if p == "" {
			p = "/"
		}
		q := r.URL.Query()
		switch {
		case p == "/health":
			fmt.Fprint(w, "ok")
		case p == "/echo":
			fmt.Fprint(w, "echo: "+q.Get("q"))
		case p == "/item":
			fmt.Fprint(w, item(q.Get("id")))
		case p == "/spawn":
			out, _ := exec.Command("/usr/bin/id").Output()
			fmt.Fprint(w, string(out)+"spawned")
		case p == "/sleep":
			ms, _ := strconv.Atoi(q.Get("ms"))
			if ms > 10000 {
				ms = 10000
			}
			time.Sleep(time.Duration(ms) * time.Millisecond)
			fmt.Fprint(w, "slept")
		case p == "/alloc":
			mb, _ := strconv.Atoi(q.Get("mb"))
			if mb < 1 {
				mb = 1
			}
			if mb > 256 {
				mb = 256
			}
			b := make([]byte, mb*1024*1024)
			b[0] = 1
			fmt.Fprintf(w, "alloc %d (%d)", mb, b[0])
		case p == "/upload" && r.Method == "POST":
			os.MkdirAll(filepath.Join(root, "uploads"), 0750)
			name := regexp.MustCompile(`[^A-Za-z0-9._-]`).ReplaceAllString(q.Get("name"), "_")
			if name == "" {
				name = "upload.bin"
			}
			buf := make([]byte, 262144)
			n, _ := r.Body.Read(buf)
			os.WriteFile(filepath.Join(root, "uploads", name), buf[:n], 0640)
			fmt.Fprint(w, "stored uploads/"+name)
		default:
			http.Error(w, "not found", 404)
		}
	})
	addr := "127.0.0.1:" + port
	srv := &http.Server{Addr: addr, Handler: mux, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second}
	_ = strings.TrimSpace
	srv.ListenAndServe()
}
