package checker

// setValues assigns the payload to an empty form's attribute.
func setValues(v map[string]string, payload string) {
	for k, val := range v {
		if val == "" {
			v[k] = payload
		}
	}
}

// copyMap copies values of the entire map into the new one.
func copyMap(m map[string]string) map[string]string {
	m2 := make(map[string]string, len(m))
	for k, v := range m {
		m2[k] = v
	}

	return m2
}

// deleteEmpty deletes empty slice elements.
func deleteEmpty(s []string) []string {
	var result []string
	for _, str := range s {
		if str != "" {
			result = append(result, str)
		}
	}

	return result
}
