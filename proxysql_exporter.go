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
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	"github.com/shatteredsilicon/exporter_shared"
	"gopkg.in/ini.v1"
)

const (
	program           = "proxysql_exporter"
	defaultDataSource = "stats:stats@tcp(localhost:6032)/"
)

var (
	versionF       = flag.Bool("version", false, "Print version information and exit.")
	configPath     = flag.String("config", "/opt/ss/ssm-client/proxysql_exporter.conf", "Path of config file")
	listenAddressF = flag.String("web.listen-address", ":42004", "Address to listen on for web interface and telemetry.")
	telemetryPathF = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")

	mysqlStatusF         = flag.Bool("collect.mysql_status", true, "Collect from stats_mysql_global (SHOW MYSQL STATUS).")
	mysqlConnectionPoolF = flag.Bool("collect.mysql_connection_pool", true, "Collect from stats_mysql_connection_pool.")
)

var cfg = new(config)

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

	err := ini.MapTo(cfg, *configPath)
	if err != nil {
		log.Fatal(fmt.Sprintf("Load config file %s failed: %s", *configPath, err.Error()))
	}

	// set flags for exporter_shared server
	flag.Set("web.ssl-cert-file", lookupConfig("web.ssl-cert-file", "").(string))
	flag.Set("web.ssl-key-file", lookupConfig("web.ssl-key-file", "").(string))

	dsn := os.Getenv("DATA_SOURCE_NAME")
	if dsn == "" {
		dsn = lookupConfig("dsn", "").(string)
	}
	if dsn == "" {
		dsn = defaultDataSource
	}

	log.Infof("Starting %s %s for %s", program, version.Version, dsn)

	exporter := NewExporter(dsn, lookupConfig("collect.mysql_status", *mysqlStatusF).(bool), lookupConfig("collect.mysql_connection_pool", *mysqlConnectionPoolF).(bool))
	prometheus.MustRegister(exporter)

	exporter_shared.RunServer("ProxySQL", lookupConfig("web.listen-address", *listenAddressF).(string), lookupConfig("web.telemetry-path", *telemetryPathF).(string), promhttp.ContinueOnError)
}

type config struct {
	Web webConfig `ini:"web"`
}

type webConfig struct {
	ListenAddress string `ini:"listen-address"`
	MetricsPath   string `ini:"telemetry-path"`
	SSLCertFile   string `ini:"ssl-cert-file"`
	SSLKeyFile    string `ini:"ssl-key-file"`
}

type collectConfig struct {
	MysqlStatus         bool `ini:"mysql_status"`
	MysqlConnectionPool bool `ini:"mysql_connection_pool"`
}

// lookupConfig lookup config from flag
// or config by name, returns nil if none exists.
// name should be in this format -> '[section].[key]'
func lookupConfig(name string, defaultValue interface{}) interface{} {
	var flagSet bool
	var flagValue interface{}
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			flagSet = true
			switch reflect.Indirect(reflect.ValueOf(f.Value)).Kind() {
			case reflect.Bool:
				flagValue = reflect.Indirect(reflect.ValueOf(f.Value)).Bool()
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				flagValue = reflect.Indirect(reflect.ValueOf(f.Value)).Int()
			case reflect.Float32, reflect.Float64:
				flagValue = reflect.Indirect(reflect.ValueOf(f.Value)).Float()
			case reflect.String:
				flagValue = reflect.Indirect(reflect.ValueOf(f.Value)).String()
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				flagValue = reflect.Indirect(reflect.ValueOf(f.Value)).Uint()
			}
		}
	})
	if flagSet {
		return flagValue
	}

	section := ""
	key := name
	if i := strings.Index(name, "."); i > 0 {
		section = name[0:i]
		if len(name) > i+1 {
			key = name[i+1:]
		} else {
			key = ""
		}
	}

	t := reflect.TypeOf(*cfg)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		iniName := field.Tag.Get("ini")
		matched := iniName == section
		if section == "" {
			matched = iniName == key
		}
		if !matched {
			continue
		}

		v := reflect.ValueOf(cfg).Elem().Field(i)
		if section == "" {
			return v.Interface()
		}

		if !v.CanAddr() {
			continue
		}

		st := reflect.TypeOf(v.Interface())
		for j := 0; j < st.NumField(); j++ {
			sectionField := st.Field(j)
			sectionININame := sectionField.Tag.Get("ini")
			if sectionININame != key {
				continue
			}

			return v.Addr().Elem().Field(j).Interface()
		}
	}

	return defaultValue
}
