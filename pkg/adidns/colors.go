package adidns

func GetPropCellColor(propId uint32, cellValue string) (string, bool) {
	switch cellValue {
	case "Enabled":
		return "green", true
	case "Disabled", "None":
		return "red", true
	case "Unknown", "Not specified":
		return "gray", true
	}

	switch propId {
	case 0x00000001:
		switch cellValue {
		case "PRIMARY":
			return "green", true
		case "CACHE":
			return "blue", true
		}
	case 0x00000002:
		switch cellValue {
		case "None":
			return "red", true
		case "Nonsecure and secure":
			return "yellow", true
		case "Secure only":
			return "green", true
		default:
			return "gray", true
		}
	}

	return "", false
}
