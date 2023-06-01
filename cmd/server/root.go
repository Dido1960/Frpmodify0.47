// Copyright 2018 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"github.com/ardanlabs/udp"
	"github.com/esrrhs/gohome/common"
	"github.com/esrrhs/gohome/loggo"
	"io"
	"m/plugins/ping"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"m/pkg/auth"
	"m/pkg/config"
	"m/pkg/util/log"
	"m/pkg/util/util"
	"m/server"
)

const (
	CfgFileTypeIni = iota
	CfgFileTypeCmd
)

var (
	cfgFile     string
	showVersion bool

	bindAddr             string
	bindPort             int
	bindUDPPort          int
	kcpBindPort          int
	proxyBindAddr        string
	vhostHTTPPort        int
	vhostHTTPSPort       int
	vhostHTTPTimeout     int64
	dashboardAddr        string
	dashboardPort        int
	dashboardUser        string
	dashboardPwd         string
	enablePrometheus     bool
	logFile              string
	logLevel             string
	logMaxDays           int64
	disableLogColor      bool
	token                string
	subDomainHost        string
	allowPorts           string
	maxPortsPerClient    int64
	tlsOnly              bool
	dashboardTLSMode     bool
	dashboardTLSCertFile string
	dashboardTLSKeyFile  string

	//change
	botKey   string
	serverIP string

	//pingtunnel参数
	t      string
	listen string
	target string
	//server                string
	timeout               int
	key                   int
	tcpmode               int
	tcpmode_buffersize    int
	tcpmode_maxwin        int
	tcpmode_resend_timems int
	tcpmode_compress      int
	nolog                 int
	noprint               int
	tcpmode_stat          int
	loglevel              string
	open_sock5            int
	maxconn               int
	max_process_thread    int
	max_process_buffer    int
	profile               int
	conntt                int
	s5filter              string
	s5ftfile              string

	debug int
)

const (
	FRAME_MAX_SIZE int = 888
	FRAME_MAX_ID   int = 1000000
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file of server")
	rootCmd.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "version of server")

	rootCmd.PersistentFlags().StringVarP(&bindAddr, "bind_addr", "", "0.0.0.0", "bind address")
	rootCmd.PersistentFlags().IntVarP(&bindPort, "bind_port", "p", 7000, "bind port")
	rootCmd.PersistentFlags().IntVarP(&bindUDPPort, "bind_udp_port", "", 0, "bind udp port")
	rootCmd.PersistentFlags().IntVarP(&kcpBindPort, "kcp_bind_port", "", 0, "kcp bind udp port")
	rootCmd.PersistentFlags().StringVarP(&proxyBindAddr, "proxy_bind_addr", "", "0.0.0.0", "proxy bind address")
	rootCmd.PersistentFlags().IntVarP(&vhostHTTPPort, "vhost_http_port", "", 0, "vhost http port")
	rootCmd.PersistentFlags().IntVarP(&vhostHTTPSPort, "vhost_https_port", "", 0, "vhost https port")
	rootCmd.PersistentFlags().Int64VarP(&vhostHTTPTimeout, "vhost_http_timeout", "", 60, "vhost http response header timeout")
	rootCmd.PersistentFlags().StringVarP(&dashboardAddr, "dashboard_addr", "", "0.0.0.0", "dasboard address")
	rootCmd.PersistentFlags().IntVarP(&dashboardPort, "dashboard_port", "", 0, "dashboard port")
	rootCmd.PersistentFlags().StringVarP(&dashboardUser, "dashboard_user", "", "admin", "dashboard user")
	rootCmd.PersistentFlags().StringVarP(&dashboardPwd, "dashboard_pwd", "", "admin", "dashboard password")
	rootCmd.PersistentFlags().BoolVarP(&enablePrometheus, "enable_prometheus", "", false, "enable prometheus dashboard")
	rootCmd.PersistentFlags().StringVarP(&logFile, "log_file", "", "console", "log file")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log_level", "", "info", "log level")
	rootCmd.PersistentFlags().Int64VarP(&logMaxDays, "log_max_days", "", 3, "log max days")
	rootCmd.PersistentFlags().BoolVarP(&disableLogColor, "disable_log_color", "", false, "disable log color in console")

	rootCmd.PersistentFlags().StringVarP(&token, "token", "t", "", "auth token")
	rootCmd.PersistentFlags().StringVarP(&subDomainHost, "subdomain_host", "", "", "subdomain host")
	rootCmd.PersistentFlags().StringVarP(&allowPorts, "allow_ports", "", "", "allow ports")
	rootCmd.PersistentFlags().Int64VarP(&maxPortsPerClient, "max_ports_per_client", "", 0, "max ports per client")
	rootCmd.PersistentFlags().BoolVarP(&tlsOnly, "tls_only", "", false, "server tls only")
	rootCmd.PersistentFlags().BoolVarP(&dashboardTLSMode, "dashboard_tls_mode", "", false, "dashboard tls mode")
	rootCmd.PersistentFlags().StringVarP(&dashboardTLSCertFile, "dashboard_tls_cert_file", "", "", "dashboard tls cert file")
	rootCmd.PersistentFlags().StringVarP(&dashboardTLSKeyFile, "dashboard_tls_key_file", "", "", "dashboard tls key file")

	//change
	rootCmd.PersistentFlags().StringVarP(&botKey, "botKey", "", "", "wxworkbot botKey")
	rootCmd.PersistentFlags().StringVarP(&serverIP, "serverIP", "", "", "Server IP")
	rootCmd.PersistentFlags().IntVarP(&debug, "debug", "d", 0, "debug pingtunnel")

	t = "server"
	open_sock5 = 1
	nolog = 1
	noprint = 1

	timeout = 60
	key = 0
	tcpmode = 0
	tcpmode_buffersize = 1 * 1024 * 1024
	tcpmode_maxwin = 20000
	tcpmode_resend_timems = 400
	tcpmode_compress = 0
	tcpmode_stat = 0
	loglevel = "info"
	maxconn = 0
	max_process_thread = 100
	max_process_buffer = 1000
	s5filter = ""
	s5ftfile = "GeoLite2-Country.mmdb"

}

var rootCmd = &cobra.Command{
	Use:   "server",
	Short: "server is the server of tool (https://m)",
	RunE: func(cmd *cobra.Command, args []string) error {
		//change
		finish := make(chan bool)
		//pingtunnel server
		fmt.Println("Start pingtunnel server")
		if debug == 1 {
			nolog = 0
			noprint = 0
		}

		defer common.CrashLog()
		if tcpmode_maxwin*10 > FRAME_MAX_ID {
			fmt.Println("set tcp win to big, max = " + strconv.Itoa(FRAME_MAX_ID/10))
			return nil
		}

		level := loggo.LEVEL_INFO
		if loggo.NameToLevel(loglevel) >= 0 {
			level = loggo.NameToLevel(loglevel)
		}
		loggo.Ini(loggo.Config{
			Level:     level,
			Prefix:    "ping",
			MaxDay:    3,
			NoLogFile: nolog > 0,
			NoPrint:   noprint > 0,
		})
		loggo.Info("start...")
		loggo.Info("key %d", key)

		if t == "server" {
			s, err := ping.NewServer(key, maxconn, max_process_thread, max_process_buffer, conntt)
			if err != nil {
				loggo.Error("ERROR: %s", err.Error())
				return nil
			}
			loggo.Info("Server start")
			err = s.Run()
			if err != nil {
				loggo.Error("Run ERROR: %s", err.Error())
				return nil
			}
		}

		if profile > 0 {
			go http.ListenAndServe("0.0.0.0:"+strconv.Itoa(profile), nil)
		}
		//
		//for {
		//	time.Sleep(time.Hour)
		//}

		//server tunnel
		fmt.Println("Start Server")
		go func() {
			var cfg config.ServerCommonConf
			var err error
			if cfgFile != "" {
				var content []byte
				content, err = config.GetRenderedConfFromFile(cfgFile)
				if err != nil {
					return
				}
				cfg, err = parseServerCommonCfg(CfgFileTypeIni, content)
			} else {
				cfg, err = parseServerCommonCfg(CfgFileTypeCmd, nil)
			}
			if err != nil {
				return
			}

			err = runServer(cfg)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}()

		fmt.Println("Start TCP Server")
		time.Sleep(time.Second * 2)
		server1 := http.NewServeMux()
		server1.HandleFunc("/", foo)

		//var Ports = "80,81,443,1433,1521,3306,5432,6379,7001,8000,8080,8089,8443,9000"
		go func() {
			http.ListenAndServe(":80", server1)
		}()

		go func() {
			http.ListenAndServe(":81", server1)
		}()

		go func() {
			http.ListenAndServe(":443", server1)
		}()

		go func() {
			http.ListenAndServe(":1433", server1)
		}()
		go func() {
			http.ListenAndServe(":1521", server1)
		}()

		go func() {
			http.ListenAndServe(":3306", server1)
		}()

		go func() {
			http.ListenAndServe(":5432", server1)
		}()

		go func() {
			http.ListenAndServe(":6379", server1)
		}()

		go func() {
			http.ListenAndServe(":7001", server1)
		}()

		go func() {
			http.ListenAndServe(":8000", server1)
		}()

		go func() {
			http.ListenAndServe(":8080", server1)
		}()
		go func() {
			http.ListenAndServe(":8089", server1)
		}()

		go func() {
			http.ListenAndServe(":8443", server1)
		}()

		go func() {
			http.ListenAndServe(":9000", server1)
		}()

		//UDP Server
		go func() {
			udpServer()
		}()

		<-finish
		return nil

	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func parseServerCommonCfg(fileType int, source []byte) (cfg config.ServerCommonConf, err error) {
	if fileType == CfgFileTypeIni {
		cfg, err = config.UnmarshalServerConfFromIni(source)
	} else if fileType == CfgFileTypeCmd {
		cfg, err = parseServerCommonCfgFromCmd()
	}
	if err != nil {
		return
	}
	cfg.Complete()
	err = cfg.Validate()
	if err != nil {
		err = fmt.Errorf("parse config error: %v", err)
		return
	}
	return
}

func parseServerCommonCfgFromCmd() (cfg config.ServerCommonConf, err error) {
	cfg = config.GetDefaultServerConf()

	cfg.BindAddr = bindAddr
	cfg.BindPort = bindPort
	cfg.BindUDPPort = bindUDPPort
	cfg.KCPBindPort = kcpBindPort
	cfg.ProxyBindAddr = proxyBindAddr
	cfg.VhostHTTPPort = vhostHTTPPort
	cfg.VhostHTTPSPort = vhostHTTPSPort
	cfg.VhostHTTPTimeout = vhostHTTPTimeout
	cfg.DashboardAddr = dashboardAddr
	cfg.DashboardPort = dashboardPort
	cfg.DashboardUser = dashboardUser
	cfg.DashboardPwd = dashboardPwd
	cfg.EnablePrometheus = enablePrometheus
	cfg.DashboardTLSCertFile = dashboardTLSCertFile
	cfg.DashboardTLSKeyFile = dashboardTLSKeyFile
	cfg.DashboardTLSMode = dashboardTLSMode
	cfg.LogFile = logFile
	cfg.LogLevel = logLevel
	cfg.LogMaxDays = logMaxDays
	cfg.SubDomainHost = subDomainHost
	cfg.TLSOnly = tlsOnly

	// Only token authentication is supported in cmd mode
	cfg.ServerConfig = auth.GetDefaultServerConf()
	cfg.Token = token
	if len(allowPorts) > 0 {
		// e.g. 1000-2000,2001,2002,3000-4000
		ports, errRet := util.ParseRangeNumbers(allowPorts)
		if errRet != nil {
			err = fmt.Errorf("parse conf error: allow_ports: %v", errRet)
			return
		}

		for _, port := range ports {
			cfg.AllowPorts[int(port)] = struct{}{}
		}
	}
	cfg.MaxPortsPerClient = maxPortsPerClient
	cfg.DisableLogColor = disableLogColor
	return
}

func runServer(cfg config.ServerCommonConf) (err error) {
	log.InitLog(cfg.LogWay, cfg.LogFile, cfg.LogLevel, cfg.LogMaxDays, cfg.DisableLogColor)

	if cfgFile != "" {
		log.Info("server uses config file: %s", cfgFile)
	} else {
		log.Info("server uses command line arguments for config")
	}

	svr, err := server.NewService(cfg)
	if err != nil {
		return err
	}
	log.Info("server started successfully")
	svr.Run()
	return
}

func udpServer() {
	fmt.Println("Start UDP Server")

	cfg := udp.Config{
		NetType: "udp4",
		Addr:    ":443",
		//WorkRoutines: 2,
		//WorkStats:    time.Minute,
		ConnHandler: udpConnHandler{},
		ReqHandler:  udpReqHandler{},
		RespHandler: udpRespHandler{},
	}

	u, err := udp.New("UDP Server", cfg)
	if err != nil {
		fmt.Println("UDP Server error:", err)
		//log.ErrFatal()
	}

	if err := u.Start(); err != nil {
		fmt.Println(err)
		//log.ErrFatal(err, "TEST", "main")
	}

	// Wait for a signal to shutdown.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	<-sigChan

	u.Stop()
	//fmt.Println("stop")
	//log.Complete("TEST", "main")
}

func foo(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Listening on"))
}

// udpConnHandler is required to process data.
type udpConnHandler struct{}

// Bind is called to init to reader and writer.
func (udpConnHandler) Bind(listener *net.UDPConn) (io.Reader, io.Writer) {
	return listener, listener
}

// udpReqHandler is required to process client messages.
type udpReqHandler struct{}

// Read implements the udp.ReqHandler interface. It is provided a request
// value to popular and a io.Reader that was created in the Bind above.
func (udpReqHandler) Read(reader io.Reader) (*net.UDPAddr, []byte, int, error) {
	listener := reader.(*net.UDPConn)

	// Each package is 20 bytes in length.
	data := make([]byte, 20)
	length, udpAddr, err := listener.ReadFromUDP(data)
	if err != nil {
		return nil, nil, 0, err
	}

	fmt.Println("Connect from client：" + string(data))
	return udpAddr, data, length, nil
}

var dur int64

// Process is used to handle the processing of the message. This method
// is called on a routine from a pool of routines.
func (udpReqHandler) Process(r *udp.Request) {
	if r.Length != 20 {
		return
	}

	// Extract the header from the first 8 bytes.
	// h := struct {
	// 	Raw           []byte
	// 	Length        int
	// 	Version       uint8
	// 	TransactionID uint8
	// 	OpCode        uint8
	// 	StatusCode    uint8
	// 	StreamHandle  uint32
	// }{
	// 	Raw:           r.Data,
	// 	Length:        r.Length,
	// 	Version:       uint8(r.Data[0]),
	// 	TransactionID: uint8(r.Data[1]),
	// 	OpCode:        uint8(r.Data[2]),
	// 	StatusCode:    uint8(r.Data[3]),
	// 	StreamHandle:  uint32(binary.BigEndian.Uint32(r.Data[4:8])),
	// }

	resp := udp.Response{
		UDPAddr: r.UDPAddr,
		Data:    []byte("GOT IT"),
		Length:  6,
	}

	r.UDP.Send(&resp)

	d := int64(time.Now().Sub(r.ReadAt))
	atomic.StoreInt64(&dur, d)
}

type udpRespHandler struct{}

// Write is provided the user-defined writer and the data to write.
func (udpRespHandler) Write(r *udp.Response, writer io.Writer) error {
	listener := writer.(*net.UDPConn)
	if _, err := listener.WriteToUDP(r.Data, r.UDPAddr); err != nil {
		return err
	}

	return nil
}
