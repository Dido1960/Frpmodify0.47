package basic

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/onsi/ginkgo"

	"m/test/e2e/framework"
	"m/test/e2e/pkg/request"
)

const (
	ConfigValidStr = "syntax is ok"
)

var _ = ginkgo.Describe("[Feature: Cmd]", func() {
	f := framework.NewDefaultFramework()

	ginkgo.Describe("Verify", func() {
		ginkgo.It("server valid", func() {
			path := f.GenerateConfigFile(`
			[common]
			bind_addr = 0.0.0.0
			bind_port = 7000
			`)
			_, output, err := f.RunTools("verify", "-c", path)
			framework.ExpectNoError(err)
			framework.ExpectTrue(strings.Contains(output, ConfigValidStr), "output: %s", output)
		})
		ginkgo.It("server invalid", func() {
			path := f.GenerateConfigFile(`
			[common]
			bind_addr = 0.0.0.0
			bind_port = 70000
			`)
			_, output, err := f.RunTools("verify", "-c", path)
			framework.ExpectNoError(err)
			framework.ExpectTrue(!strings.Contains(output, ConfigValidStr), "output: %s", output)
		})
		ginkgo.It("client valid", func() {
			path := f.GenerateConfigFile(`
			[common]
			server_addr = 0.0.0.0
			server_port = 7000
			`)
			_, output, err := f.RunToolc("verify", "-c", path)
			framework.ExpectNoError(err)
			framework.ExpectTrue(strings.Contains(output, ConfigValidStr), "output: %s", output)
		})
		ginkgo.It("client invalid", func() {
			path := f.GenerateConfigFile(`
			[common]
			server_addr = 0.0.0.0
			server_port = 7000
			protocol = invalid
			`)
			_, output, err := f.RunToolc("verify", "-c", path)
			framework.ExpectNoError(err)
			framework.ExpectTrue(!strings.Contains(output, ConfigValidStr), "output: %s", output)
		})
	})

	ginkgo.Describe("Single proxy", func() {
		ginkgo.It("TCP", func() {
			serverPort := f.AllocPort()
			_, _, err := f.RunTools("-t", "123", "-p", strconv.Itoa(serverPort))
			framework.ExpectNoError(err)

			localPort := f.PortByName(framework.TCPEchoServerPort)
			remotePort := f.AllocPort()
			_, _, err = f.RunToolc("tcp", "-s", fmt.Sprintf("127.0.0.1:%d", serverPort), "-t", "123", "-u", "test",
				"-l", strconv.Itoa(localPort), "-r", strconv.Itoa(remotePort), "-n", "tcp_test")
			framework.ExpectNoError(err)

			framework.NewRequestExpect(f).Port(remotePort).Ensure()
		})

		ginkgo.It("UDP", func() {
			serverPort := f.AllocPort()
			_, _, err := f.RunTools("-t", "123", "-p", strconv.Itoa(serverPort))
			framework.ExpectNoError(err)

			localPort := f.PortByName(framework.UDPEchoServerPort)
			remotePort := f.AllocPort()
			_, _, err = f.RunToolc("udp", "-s", fmt.Sprintf("127.0.0.1:%d", serverPort), "-t", "123", "-u", "test",
				"-l", strconv.Itoa(localPort), "-r", strconv.Itoa(remotePort), "-n", "udp_test")
			framework.ExpectNoError(err)

			framework.NewRequestExpect(f).Protocol("udp").
				Port(remotePort).Ensure()
		})

		ginkgo.It("HTTP", func() {
			serverPort := f.AllocPort()
			vhostHTTPPort := f.AllocPort()
			_, _, err := f.RunTools("-t", "123", "-p", strconv.Itoa(serverPort), "--vhost_http_port", strconv.Itoa(vhostHTTPPort))
			framework.ExpectNoError(err)

			_, _, err = f.RunToolc("http", "-s", "127.0.0.1:"+strconv.Itoa(serverPort), "-t", "123", "-u", "test",
				"-n", "udp_test", "-l", strconv.Itoa(f.PortByName(framework.HTTPSimpleServerPort)),
				"--custom_domain", "test.example.com")
			framework.ExpectNoError(err)

			framework.NewRequestExpect(f).Port(vhostHTTPPort).
				RequestModify(func(r *request.Request) {
					r.HTTP().HTTPHost("test.example.com")
				}).
				Ensure()
		})
	})
})
