package policy

type Policy struct {
	Name        string
	Description string
}

type Set []Policy

func DefaultSet() Set {
	return Set{
		{
			Name:        "baseline",
			Description: "Default policy placeholder for Argus.",
		},
	}
}
