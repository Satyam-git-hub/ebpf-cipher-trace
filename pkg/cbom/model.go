package cbom

// CBOM represents the Cryptographic Bill of Materials
type CBOM struct {
	BOMFormat   string    `json:"bomFormat"`
	SpecVersion string    `json:"specVersion"`
	SerialNumber string   `json:"serialNumber"`
	Version     int       `json:"version"`
	Metadata    Metadata  `json:"metadata"`
	Components  []Component `json:"components"`
}

type Metadata struct {
	Timestamp string `json:"timestamp"`
	Tools     []Tool `json:"tools"`
}

type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Component struct {
	Type        string            `json:"type"` // e.g., "crypto-asset"
	Name        string            `json:"name"`
	Properties  []Property        `json:"properties"`
	PURL        string            `json:"purl"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// EventToCBOM converts a raw event to a CBOM component
func EventToCBOM(event interface{}) Component {
	// Placeholder logic
	return Component{
		Type: "crypto-asset",
		Name: "Calculated from Event",
	}
}
