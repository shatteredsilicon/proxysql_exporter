// Copyright 2016-2017 Percona LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	"github.com/shatteredsilicon/ssm-client/pmm"
	"github.com/shatteredsilicon/ssm-client/pmm/plugin"
)

const (
	program           = "proxysql_exporter"
	defaultDataSource = "stats:stats@tcp(localhost:6032)/"
)

var (
	versionF       = flag.Bool("version", false, "Print version information and exit.")
	listenAddressF = flag.String("web.listen-address", ":42004", "Address to listen on for web interface and telemetry.")
	telemetryPathF = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")

	mysqlStatusF         = flag.Bool("collect.mysql_status", true, "Collect from stats_mysql_global (SHOW MYSQL STATUS).")
	mysqlConnectionPoolF = flag.Bool("collect.mysql_connection_pool", true, "Collect from stats_mysql_connection_pool.")

	sslCertFile = flag.String(
		"web.ssl-cert-file", "",
		"Path to SSL certificate file.",
	)
	sslKeyFile = flag.String(
		"web.ssl-key-file", "",
		"Path to SSL key file.",
	)
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s %s exports various ProxySQL metrics in Prometheus format.\n", os.Args[0], version.Version)
		fmt.Fprintf(os.Stderr, "It uses DATA_SOURCE_NAME environment variable with following format: https://github.com/go-sql-driver/mysql#dsn-data-source-name\n")
		fmt.Fprintf(os.Stderr, "Default value is %q.\n\n", defaultDataSource)
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *versionF {
		fmt.Println(version.Print(program))
		os.Exit(0)
	}

	dsn := os.Getenv("DATA_SOURCE_NAME")
	if dsn == "" {
		dsn = defaultDataSource
	}

	log.Infof("Starting %s %s for %s", program, version.Version, dsn)

	exporter := NewExporter(dsn, *mysqlStatusF, *mysqlConnectionPoolF)
	prometheus.MustRegister(exporter)

	// New http server
	mux := http.NewServeMux()
	srv := &http.Server{
		Addr:    *listenAddressF,
		Handler: mux,
	}

	landingPage := []byte(`<html>
<html>
<head>
	<title>ProxySQL exporter</title>
</head>
<body>
	<h1>ProxySQL exporter</h1>
	<p><a href="` + *telemetryPathF + `">Metrics</a></p>
</body>
</html>
`)

	ssl := false
	if *sslCertFile != "" && *sslKeyFile != "" {
		if _, err := os.Stat(*sslCertFile); os.IsNotExist(err) {
			log.Fatal("SSL certificate file does not exist: ", *sslCertFile)
		}
		if _, err := os.Stat(*sslKeyFile); os.IsNotExist(err) {
			log.Fatal("SSL key file does not exist: ", *sslKeyFile)
		}
		ssl = true
		log.Infoln("HTTPS/TLS is enabled")
	}

	log.Infoln("Listening on", *listenAddressF)

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if ssl {
			w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}

		if req.Method != http.MethodDelete {
			w.Write(landingPage)
			return
		}

		errFunc := func(w http.ResponseWriter, err error) {
			log.Errorf("remove metrics failed: %s", err.Error())

			errBytes, _ := json.Marshal(map[string]interface{}{
				"error": fmt.Sprintf("Remove metrics %s failed: %s", plugin.NameLinux, err.Error()),
			})
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json")
			w.Write(errBytes)
			return
		}

		admin := pmm.Admin{}
		err := admin.LoadConfig()
		if err != nil {
			errFunc(w, err)
			return
		}

		err = admin.SetAPI()
		if err != nil {
			errFunc(w, err)
			return
		}

		err = admin.RemoveMetrics(plugin.NameMySQL)
		if err != nil {
			errFunc(w, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})

	if ssl {
		// https
		tlsCfg := &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		}
		srv.TLSConfig = tlsCfg
		srv.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0)

		log.Fatal(srv.ListenAndServeTLS(*sslCertFile, *sslKeyFile))
	} else {
		// http
		log.Fatal(srv.ListenAndServe())
	}
}
