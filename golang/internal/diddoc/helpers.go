package diddoc

// FindVerificationMethod looks up a verification method by full identifier.
func FindVerificationMethod(didDocument map[string]any, verificationMethodID string) map[string]any {
	if methods, ok := didDocument["verificationMethod"].([]any); ok {
		for _, item := range methods {
			method, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if id, _ := method["id"].(string); id == verificationMethodID {
				return cloneMap(method)
			}
		}
	}
	if authentication, ok := didDocument["authentication"].([]any); ok {
		for _, item := range authentication {
			method, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if id, _ := method["id"].(string); id == verificationMethodID {
				return cloneMap(method)
			}
		}
	}
	if assertionMethod, ok := didDocument["assertionMethod"].([]any); ok {
		for _, item := range assertionMethod {
			method, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if id, _ := method["id"].(string); id == verificationMethodID {
				return cloneMap(method)
			}
		}
	}
	return nil
}

// IsAuthenticationAuthorized reports whether a verification method is referenced from authentication.
func IsAuthenticationAuthorized(didDocument map[string]any, verificationMethodID string) bool {
	return isVerificationMethodAuthorized(didDocument, "authentication", verificationMethodID)
}

// IsAssertionMethodAuthorized reports whether a verification method is referenced from assertionMethod.
func IsAssertionMethodAuthorized(didDocument map[string]any, verificationMethodID string) bool {
	return isVerificationMethodAuthorized(didDocument, "assertionMethod", verificationMethodID)
}

func isVerificationMethodAuthorized(didDocument map[string]any, relationship string, verificationMethodID string) bool {
	authentication, ok := didDocument[relationship].([]any)
	if !ok {
		return false
	}
	for _, entry := range authentication {
		switch typed := entry.(type) {
		case string:
			if typed == verificationMethodID {
				return true
			}
		case map[string]any:
			if id, _ := typed["id"].(string); id == verificationMethodID {
				return true
			}
		}
	}
	return false
}

func cloneMap(value map[string]any) map[string]any {
	result := make(map[string]any, len(value))
	for key, entry := range value {
		result[key] = entry
	}
	return result
}
