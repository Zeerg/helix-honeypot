package model

type HostIDStruct struct {
	MachineID         string `json:"machineId"`
	Hostname          string `json:"hostname"`
	MacAddress        []string `json:"macAddress"`
	ProcessorHash     string `json:"processorHash"`
	ProcessorFeatures string `json:"processorFeatures"`
	CacheLine         string `json:"cacheLine"`
	CacheL1D          string `json:"cacheL1D"`
	CacheL1I          string `json:"cacheL1I"`
	CacheL2           string `json:"cacheL2"`
	CacheL3           string `json:"cacheL3"`
	CPUFrequency      string `json:"cpuFrequency"`
	PhysicalCores     string `json:"physicalCores"`
	LogicalCores      string `json:"logicalCores"`
	ThreadsPerCore    string `json:"threadsPerCore"`
	VendorID          string `json:"vendorId"`
}

