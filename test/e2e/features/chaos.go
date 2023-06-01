package features

import (
	"fmt"
	"time"

	"github.com/onsi/ginkgo"

	"m/test/e2e/framework"
)

var _ = ginkgo.Describe("[Feature: Chaos]", func() {
	f := framework.NewDefaultFramework()

	ginkgo.It("reconnect after server restart", func() {
		serverPort := f.AllocPort()
		serverConfigPath := f.GenerateConfigFile(fmt.Sprintf(`
		[common]
		bind_addr = 0.0.0.0
		bind_port = %d
		`, serverPort))

		remotePort := f.AllocPort()
		clientConfigPath := f.GenerateConfigFile(fmt.Sprintf(`
		[common]
		server_port = %d
		log_level = trace

		[tcp]
		type = tcp
		local_port = %d
		remote_port = %d
		`, serverPort, f.PortByName(framework.TCPEchoServerPort), remotePort))

		// 1. start server and client, expect request success
		ps, _, err := f.RunTools("-c", serverConfigPath)
		framework.ExpectNoError(err)

		pc, _, err := f.RunToolc("-c", clientConfigPath)
		framework.ExpectNoError(err)
		framework.NewRequestExpect(f).Port(remotePort).Ensure()

		// 2. stop server, expect request failed
		_ = ps.Stop()
		time.Sleep(200 * time.Millisecond)
		framework.NewRequestExpect(f).Port(remotePort).ExpectError(true).Ensure()

		// 3. restart server, expect request success
		_, _, err = f.RunTools("-c", serverConfigPath)
		framework.ExpectNoError(err)
		time.Sleep(2 * time.Second)
		framework.NewRequestExpect(f).Port(remotePort).Ensure()

		// 4. stop client, expect request failed
		_ = pc.Stop()
		time.Sleep(200 * time.Millisecond)
		framework.NewRequestExpect(f).Port(remotePort).ExpectError(true).Ensure()

		// 5. restart client, expect request success
		_, _, err = f.RunToolc("-c", clientConfigPath)
		framework.ExpectNoError(err)
		time.Sleep(time.Second)
		framework.NewRequestExpect(f).Port(remotePort).Ensure()
	})
})
