package framework

type TOOLClient struct {
	port int
}

func (f *Framework) TOOLClient(port int) *TOOLClient {
	return &TOOLClient{
		port: port,
	}
}
