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
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	_ "github.com/go-sql-driver/mysql"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/promslog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v2"
)

const (
	program             = "proxysql_exporter"
	defaultDataSource   = "stats:stats@tcp(localhost:6032)/"
	webAuthFileFlagName = "web.auth-file"
)

var (
	configPath = kingpin.Flag(
		"config",
		"Path of config file",
	).Default("/opt/ss/ssm-client/proxysql_exporter.conf").String()

	listenAddress = kingpin.Flag(
		"web.listen-address",
		"Address to listen on for web interface and telemetry.",
	).Strings()

	telemetryPathF = kingpin.Flag(
		"web.telemetry-path",
		"Path under which to expose metrics.",
	).Default("/metrics").String()

	webAuthFile     = kingpin.Flag("web.auth-file", "Path to YAML file with server_user, server_password keys for HTTP Basic authentication.").String()
	webConfigFile   = kingpin.Flag("web.config.file", "Path to prometheus web config file (YAML).").Default("/opt/ss/ssm-client/proxysql_exporter.yml").String()
	tlsMinVersion   = kingpin.Flag("web.tls-min-version", "Minimum TLS version that is acceptable.").String()
	tlsMaxVersion   = kingpin.Flag("web.tls-max-version", "Maximum TLS version that is acceptable.").String()
	tlsCipherSuites = kingpin.Flag(
		"web.tls-cipher-suites",
		"A list of enabled TLS 1.0–1.2 cipher suites. Check full list at https://github.com/golang/go/blob/master/src/crypto/tls/cipher_suites.go",
	).Strings()
	sslCertFile = kingpin.Flag(
		"web.ssl-cert-file",
		"Path to SSL certificate file.",
	).String()
	sslKeyFile = kingpin.Flag(
		"web.ssl-key-file",
		"Path to SSL key file.",
	).String()
	systemdSocket = kingpin.Flag(
		"web.systemd-socket",
		"Use systemd socket activation listeners instead of port listeners (Linux only).",
	).Bool()

	mysqlStatusF = kingpin.Flag(
		"collect.mysql_status",
		"Collect from stats_mysql_global (SHOW MYSQL STATUS).",
	).Bool()

	mysqlConnectionPoolF = kingpin.Flag(
		"collect.mysql_connection_pool",
		"Collect from stats_mysql_connection_pool.",
	).Bool()

	_ = kingpin.Flag("c", "").Hidden().Short('c').Action(convertFlagAction('c')).Strings()
	_ = kingpin.Flag("w", "").Hidden().Short('w').Action(convertFlagAction('w')).Strings()
	_ = kingpin.Flag("e", "").Hidden().Short('e').Action(convertFlagAction('e')).Strings()
	_ = kingpin.Flag("t", "").Hidden().Short('t').Action(convertFlagAction('t')).Strings()
)

var cfg = new(config)
var setByUserMap = make(map[string]bool)

func init() {
	kingpin.CommandLine.PreAction(setByUserFlagAction())
}

func setByUserFlagAction() func(ctx *kingpin.ParseContext) error {
	executed := false

	return func(pc *kingpin.ParseContext) error {
		if executed {
			return nil
		}

		for _, elem := range pc.Elements {
			if elem.Clause == nil {
				continue
			}

			flagClause, ok := elem.Clause.(*kingpin.FlagClause)
			if !ok || flagClause == nil {
				continue
			}

			setByUserMap[flagClause.Model().Name] = true
		}

		executed = true
		return nil
	}
}

func main() {
	kingpin.CommandLine.Help = fmt.Sprintf(
		"%s %s exports various ProxySQL metrics in Prometheus format. "+
			"It uses DATA_SOURCE_NAME environment variable with following format: https://github.com/go-sql-driver/mysql#dsn-data-source-name, "+
			"default value is %q.",
		program, version.Version, defaultDataSource,
	)

	kingpin.Version(version.Print(program))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	promslogConfig := &promslog.Config{}
	flag.AddFlags(kingpin.CommandLine, promslogConfig)
	if os.Getenv("DEBUG") == "1" {
		promslogConfig.Level.Set("debug")
	}
	logger := promslog.New(promslogConfig)
	slog.SetDefault(logger)

	if os.Getenv("ON_CONFIGURE") == "1" {
		err := configure()
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	err := ini.MapTo(cfg, *configPath)
	if err != nil {
		slog.Error(fmt.Sprintf("Load config file %s failed: %s", *configPath, err.Error()))
		os.Exit(1)
	}

	// override flag value with config value
	// if it's not set
	overrideFlags()

	dsn := os.Getenv("DATA_SOURCE_NAME")
	if dsn == "" {
		dsn = cfg.DSN
	}
	if dsn == "" {
		dsn = defaultDataSource
	}

	slog.Info(fmt.Sprintf("Starting %s %s for %s", program, version.Version, dsn))

	exporter := NewExporter(dsn, *mysqlStatusF, *mysqlConnectionPoolF)
	handlerFunc := newHandler(exporter)
	http.Handle(*telemetryPathF, promhttp.InstrumentMetricHandler(prometheus.DefaultRegisterer, handlerFunc))

	var authC authConfig
	if *webAuthFile != "" {
		authConfigBytes, err := os.ReadFile(*webAuthFile)
		if err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}
		if err := yaml.Unmarshal(authConfigBytes, &authC); err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}
	}

	tlsMinVer := (web.TLSVersion)(tls.VersionTLS12)
	tlsMaxVer := (web.TLSVersion)(tls.VersionTLS13)
	if tlsMinVersion != nil && *tlsMinVersion != "" {
		if err := yaml.Unmarshal([]byte(*tlsMinVersion), &tlsMinVer); err != nil {
			logger.Error(fmt.Sprintf("Unsupported tls minimum version: %s", *tlsMinVersion))
			os.Exit(1)
		}
	}
	if tlsMaxVersion != nil && *tlsMaxVersion != "" {
		if err := yaml.Unmarshal([]byte(*tlsMaxVersion), &tlsMaxVer); err != nil {
			logger.Error(fmt.Sprintf("Unsupported tls maximum version: %s", *tlsMaxVersion))
			os.Exit(1)
		}
	}

	cipherSuites := []web.Cipher{}
	if tlsCipherSuites != nil && len(*tlsCipherSuites) != 0 {
		allCipherSuites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
		for _, tlsCipherSuite := range *tlsCipherSuites {
			var cipherSuite *tls.CipherSuite
			for _, v := range allCipherSuites {
				if v.Name == tlsCipherSuite {
					cipherSuite = v
					break
				}
			}
			if cipherSuite == nil {
				logger.Error(fmt.Sprintf("Unsupported cipher suite: %s", tlsCipherSuite))
				os.Exit(1)
			}
			cipherSuites = append(cipherSuites, web.Cipher(cipherSuite.ID))
		}
	}

	prometheusWebConfig := prometheusWebConfig{
		TLSConfig: prometheusTLSConfig{
			MinVersion:   &tlsMinVer,
			MaxVersion:   &tlsMaxVer,
			CipherSuites: cipherSuites,
		},
	}
	if authC.ServerUser != "" {
		hashedPsw, err := bcrypt.GenerateFromPassword([]byte(authC.ServerPassword), 0)
		if err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}
		prometheusWebConfig.Users = map[string]string{
			authC.ServerUser: string(hashedPsw),
		}
	}
	if *sslCertFile != "" || *sslKeyFile != "" {
		prometheusWebConfig.TLSConfig.TLSCertPath = *sslCertFile
		prometheusWebConfig.TLSConfig.TLSKeyPath = *sslKeyFile
	}

	if *webConfigFile == "" {
		logger.Error("Use web.config.file flag/config to tell the location of prometheus web file")
		os.Exit(1)
	}
	webConfigBytes, err := yaml.Marshal(prometheusWebConfig)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	if err = os.WriteFile(*webConfigFile, webConfigBytes, 0600); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	srv := &http.Server{}
	toolkitFlags := &web.FlagConfig{
		WebSystemdSocket:   systemdSocket,
		WebListenAddresses: listenAddress,
		WebConfigFile:      webConfigFile,
	}
	if err := web.ListenAndServe(srv, toolkitFlags, logger); err != nil {
		logger.Error("Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}

type config struct {
	Web     webConfig     `ini:"web"`
	Collect collectConfig `ini:"collect"`
	DSN     string        `ini:"dsn"`
}

type webConfig struct {
	ListenAddress string  `ini:"listen-address"`
	MetricsPath   string  `ini:"telemetry-path"`
	SSLCertFile   string  `ini:"ssl-cert-file"`
	SSLKeyFile    string  `ini:"ssl-key-file"`
	AuthFile      *string `ini:"auth-file"`
}

type collectConfig struct {
	MysqlStatus         bool `ini:"mysql_status"`
	MysqlConnectionPool bool `ini:"mysql_connection_pool"`
}

func configVisit(visitFn func(string, string, reflect.Value)) {
	type item struct {
		value   reflect.Value
		section string
	}

	items := []item{
		{
			value:   reflect.ValueOf(cfg).Elem(),
			section: "",
		},
	}
	for i := 0; i < len(items); i++ {
		for j := 0; j < items[i].value.Type().NumField(); j++ {
			fieldValue := items[i].value.Field(j)
			fieldType := items[i].value.Type().Field(j)
			section := items[i].section
			key := strings.SplitN(fieldType.Tag.Get("ini"), ",", 2)[0]

			if fieldValue.Kind() == reflect.Struct {
				if fieldValue.CanAddr() {
					if section == "" {
						section = key
					} else if section != key {
						section = fmt.Sprintf("%s.%s", section, key)
					}

					items = append(items, item{
						value:   fieldValue.Addr().Elem(),
						section: section,
					})
				}
				continue
			} else if fieldValue.Kind() == reflect.Ptr && fieldValue.Type().Elem().Kind() == reflect.String && fieldValue.IsNil() {
				continue
			}

			visitFn(section, key, fieldValue)
		}
	}
}

func configure() error {
	iniCfg, err := ini.Load(*configPath)
	if err != nil {
		return err
	}

	if err = iniCfg.MapTo(cfg); err != nil {
		return err
	}

	configVisit(func(section, key string, fieldValue reflect.Value) {
		flagKey := fmt.Sprintf("%s.%s", section, key)
		if section == "" {
			flagKey = key
		}

		setByUser := setByUserMap[flagKey]
		kingpinF := kingpin.CommandLine.GetFlag(flagKey)
		if !setByUser || kingpinF == nil {
			return
		}

		// Don't override web.auth-file config
		if flagKey == webAuthFileFlagName {
			return
		}

		iniCfg.Section(section).Key(key).SetValue(kingpinF.Model().Value.String())
	})

	if dsn := os.Getenv("DATA_SOURCE_NAME"); dsn != "" {
		iniCfg.Section("exporter").Key("dsn").SetValue(strconv.Quote(dsn))
	}

	if err = iniCfg.SaveTo(*configPath); err != nil {
		return err
	}

	return nil
}

func overrideFlags() {
	configVisit(func(section, key string, fieldValue reflect.Value) {
		flagKey := fmt.Sprintf("%s.%s", section, key)
		if section == "" {
			flagKey = key
		}

		setByUser := setByUserMap[flagKey]
		kingpinF := kingpin.CommandLine.GetFlag(flagKey)
		if setByUser || kingpinF == nil {
			return
		}

		var values []reflect.Value
		if fieldValue.Kind() == reflect.Slice {
			for i := 0; i < fieldValue.Len(); i++ {
				values = append(values, fieldValue.Index(i))
			}
		} else {
			values = []reflect.Value{fieldValue}
		}

		for i := range values {
			switch values[i].Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Float32, reflect.Int64:
				kingpinF.Model().Value.Set(strconv.FormatInt(values[i].Int(), 10))
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				kingpinF.Model().Value.Set(strconv.FormatUint(values[i].Uint(), 10))
			case reflect.Bool:
				kingpinF.Model().Value.Set(strconv.FormatBool(values[i].Bool()))
			case reflect.Ptr:
				if !values[i].IsNil() {
					if values[i].Elem().Kind() == reflect.Bool {
						kingpinF.Model().Value.Set(strconv.FormatBool(values[i].Elem().Bool()))
					} else {
						kingpinF.Model().Value.Set(values[i].Elem().String())
					}
				}
			default:
				kingpinF.Model().Value.Set(values[i].String())
			}
		}
	})
}

func newHandler(exporter *Exporter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		registry := prometheus.NewRegistry()
		registry.MustRegister(exporter)

		gatherers := prometheus.Gatherers{
			prometheus.DefaultGatherer,
			registry,
		}

		// Delegate http serving to Prometheus client library, which will call collector.Collect.
		h := promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{})
		h.ServeHTTP(w, r)
	}
}

type authConfig struct {
	ServerUser     string `yaml:"server_user,omitempty"`
	ServerPassword string `yaml:"server_password,omitempty"`
}

type prometheusWebConfig struct {
	TLSConfig prometheusTLSConfig `yaml:"tls_server_config"`
	Users     map[string]string   `yaml:"basic_auth_users"`
}

type prometheusTLSConfig struct {
	TLSCertPath  string          `yaml:"cert_file"`
	TLSKeyPath   string          `yaml:"key_file"`
	MinVersion   *web.TLSVersion `yaml:"min_version"`
	MaxVersion   *web.TLSVersion `yaml:"max_version"`
	CipherSuites []web.Cipher    `yaml:"cipher_suites,omitempty"`
}

// this function is for translating single-hyphen flags into long flags,
// to make it compatible with earily PMM/SSM version of node_exporter
func convertFlagAction(short rune) func(ctx *kingpin.ParseContext) error {
	convertedMap := make(map[rune]bool)

	return func(pc *kingpin.ParseContext) error {
		if convertedMap[short] {
			return nil
		}

		for _, elem := range pc.Elements {
			if elem.Clause == nil {
				continue
			}

			flagClause, ok := elem.Clause.(*kingpin.FlagClause)
			if !ok || flagClause.Model().Short != short {
				continue
			}

			ctx, err := kingpin.CommandLine.ParseContext([]string{fmt.Sprintf("--%c%s", short, *elem.Value)})
			if err != nil && ctx != nil && len(ctx.Elements) > 0 && ctx.Elements[0].Clause != nil {
				// with standard flag package, single-hyphen bool flag is in format
				// '-<name>=<bool>', this code block here tries to translate it into
				// kingpin long bool flag

				clause, ok := ctx.Elements[0].Clause.(*kingpin.FlagClause)
				if !ok || !clause.Model().IsBoolFlag() {
					return err
				}

				boolStrs := strings.Split(*elem.Value, "=")
				if len(boolStrs) == 1 {
					return err
				}

				var boolValue bool
				boolValue, err = strconv.ParseBool(boolStrs[len(boolStrs)-1])
				if err != nil {
					return err
				}

				if boolValue {
					ctx, err = kingpin.CommandLine.ParseContext([]string{fmt.Sprintf("--%s", clause.Model().Name)})
				} else {
					ctx, err = kingpin.CommandLine.ParseContext([]string{fmt.Sprintf("--no-%s", clause.Model().Name)})
				}
			}
			if err != nil || ctx == nil || len(ctx.Elements) == 0 || ctx.Elements[0].Clause == nil {
				return err
			}

			flag, ok := ctx.Elements[0].Clause.(*kingpin.FlagClause)
			if !ok {
				return fmt.Errorf("unknow flag")
			}

			setByUserMap[flag.Model().Name] = true
			if err = flag.Model().Value.Set(*ctx.Elements[0].Value); err != nil {
				return err
			}
		}

		convertedMap[short] = true
		return nil
	}
}
