package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/denisbrodbeck/machineid"
	. "github.com/klauspost/cpuid/v2"

	"helix-honeypot/model"
)

func getMacAddress() ([]string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("error getting network interfaces: %v", err)
	}
	var as []string
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		if a != "" {
			as = append(as, a)
		}
	}
	return as, nil
}

func MakeMachineId() (string, error) {
	// Generate a machine id from multiple values
	var hostid model.HostIDStruct
	id, err := machineid.ID()
	if err != nil {
		fmt.Errorf("error generating machine id: %v", err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Errorf("error getting hostname: %v", err)
	}
	macSlice, err := getMacAddress()
	if err != nil {
		fmt.Errorf("error getting mac address: %v", err)
	}

	hostid.MachineID = id
	hostid.ProcessorHash = CPU.BrandName
	hostid.ProcessorFeatures = strings.Join(CPU.FeatureSet(), ",")
	hostid.CacheLine = fmt.Sprint(CPU.CacheLine)
	hostid.CacheL1D = fmt.Sprint(CPU.Cache.L1D)
	hostid.CacheL1I = fmt.Sprint(CPU.Cache.L1I)
	hostid.CacheL2 = fmt.Sprint(CPU.Cache.L2)
	hostid.CacheL3 = fmt.Sprint(CPU.Cache.L3)
	hostid.CPUFrequency = fmt.Sprint(CPU.Hz)
	hostid.PhysicalCores = fmt.Sprint(CPU.PhysicalCores)
	hostid.LogicalCores = fmt.Sprint(CPU.LogicalCores)
	hostid.ThreadsPerCore = fmt.Sprint(CPU.ThreadsPerCore)
	hostid.VendorID = CPU.VendorID.String()  // convert VendorID to string
	hostid.MacAddress = macSlice
	hostid.Hostname = hostname

	hostIDBytes, err := json.Marshal(hostid)
	if err != nil {
		return "", fmt.Errorf("error marshalling hostid: %v", err)
	}
	hash := sha256.Sum256(hostIDBytes)

	return hex.EncodeToString(hash[:]), nil
}

