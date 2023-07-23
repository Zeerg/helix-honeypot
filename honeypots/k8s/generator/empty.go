package generator

type Metadata struct {
	ResourceVersion string `json:"resourceVersion"`
}

type ColumnDefinition struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Format      string `json:"format"`
	Description string `json:"description"`
	Priority    int    `json:"priority"`
}

type Table struct {
	Kind              string             `json:"kind"`
	ApiVersion        string             `json:"apiVersion"`
	Metadata          Metadata           `json:"metadata"`
	ColumnDefinitions []map[string]interface{} `json:"columnDefinitions"`
	Rows              []interface{}      `json:"rows"`
}

// ConvertMapToColumnDefinition converts a map into a ColumnDefinition struct
func ConvertMapToColumnDefinition(defMap map[string]interface{}) ColumnDefinition {
	return ColumnDefinition{
		Name:        defMap["name"].(string),
		Type:        defMap["type"].(string),
		Format:      defMap["format"].(string),
		Description: defMap["description"].(string),
		Priority:    defMap["priority"].(int),
	}
}

// GenerateEmptyList generates a Table instance with default values
func GenerateEmptyList() Table {
	columnDefs := GenerateColumnDefinitions()
	return Table{
		Kind:              "Table",
		ApiVersion:        "meta.k8s.io/v1",
		Metadata:          Metadata{ResourceVersion: "561"},
		ColumnDefinitions: columnDefs,
		Rows:              []interface{}{},
	}
}
