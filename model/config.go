package model

type HTTPConfig struct {
	Host string
	Port string
}

type DEFConfig struct {
	Host string
	Port string
}

type UDPConfig struct {
	Host string
	Port string
}

type TCPConfig struct {
	Host string
	Port string
}

type RunModeConfig struct {
	Location  string
	RunMode   string
}

type K8SConfig struct {
	APIVersion      string
	IPBase          string 
	GenerateKubeSys bool   
	GenerateRand    bool   
	Host 			string
	Port 			string
	TokenValues    []string
	TokenNames      []string
}

type MongoDBConfig struct {
	Username       string
	Password       string
	Host           string
	Database       string
	Collection     string
	URI            string
	LogToMongoDB   bool
}

type Config struct {
	HTTP               HTTPConfig
	UDP				   UDPConfig
	TCP		   	 	   TCPConfig
	K8S                K8SConfig
	DEF				   DEFConfig
	MongoDB            MongoDBConfig
	RunMode            RunModeConfig
	MachineID		   string
}
