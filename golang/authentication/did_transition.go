package authentication

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/agent-network-protocol/anp/golang/proof"
)

const (
	ANPDidSuperseded         = 1019
	ANPDidTransitionInvalid  = 1020
	ANPDidTransitionConflict = 1021
	DefaultMaxTransitionHops = 8
)

type TransitionAssurance string

const (
	TransitionAssuranceVerified         TransitionAssurance = "verified"
	TransitionAssuranceRecoveryVerified TransitionAssurance = "recovery_verified"
	TransitionAssuranceProviderAsserted TransitionAssurance = "provider_asserted"
	TransitionAssuranceUnverified       TransitionAssurance = "unverified"
)

type TransitionStatus string

const (
	TransitionStatusActive     TransitionStatus = "active"
	TransitionStatusSuperseded TransitionStatus = "superseded"
)

type TransitionErrorKind string

const (
	TransitionErrorUnsupportedProfile       TransitionErrorKind = "unsupported_profile"
	TransitionErrorInvalidDocument          TransitionErrorKind = "invalid_document"
	TransitionErrorInvalidProof             TransitionErrorKind = "invalid_proof"
	TransitionErrorRecoveryNotPreauthorized TransitionErrorKind = "recovery_not_preauthorized"
	TransitionErrorInvalidProviderAssertion TransitionErrorKind = "invalid_provider_assertion"
	TransitionErrorStablePathMismatch       TransitionErrorKind = "stable_path_mismatch"
	TransitionErrorDirectSuccessorRequired  TransitionErrorKind = "direct_successor_required"
	TransitionErrorCycle                    TransitionErrorKind = "cycle"
	TransitionErrorConflict                 TransitionErrorKind = "conflict"
	TransitionErrorMaxHopsExceeded          TransitionErrorKind = "max_hops_exceeded"
	TransitionErrorNetwork                  TransitionErrorKind = "network_error"
)

type DidTransitionError struct {
	Kind    TransitionErrorKind
	Code    int
	Message string
}

func (e *DidTransitionError) Error() string {
	return fmt.Sprintf("%s: %s", e.Kind, e.Message)
}

func newTransitionError(kind TransitionErrorKind, message string) *DidTransitionError {
	code := ANPDidTransitionInvalid
	if kind == TransitionErrorCycle || kind == TransitionErrorConflict || kind == TransitionErrorMaxHopsExceeded {
		code = ANPDidTransitionConflict
	}
	return &DidTransitionError{Kind: kind, Code: code, Message: message}
}

type DidWbaE1Profile struct {
	DID               string
	Origin            string
	StableSubjectPath string
	Fingerprint       string
}

type TransitionHop struct {
	PredecessorDID string              `json:"predecessor_did"`
	SuccessorDID   string              `json:"successor_did"`
	Assurance      TransitionAssurance `json:"assurance"`
}

type TransitionResult struct {
	RequestedDID string               `json:"requested_did"`
	CurrentDID   string               `json:"current_did"`
	Status       TransitionStatus     `json:"status"`
	Assurance    *TransitionAssurance `json:"assurance"`
	Hops         []TransitionHop      `json:"hops"`
}

type DidDocumentFetcher func(did string) (map[string]any, error)

type TransitionCache interface {
	GetSuccessor(predecessorDID string) (string, bool)
	CompareAndSet(predecessorDID string, successorDID string) bool
}

type InMemoryTransitionCache struct {
	edges map[string]string
}

func NewInMemoryTransitionCache(edges map[string]string) *InMemoryTransitionCache {
	copyEdges := make(map[string]string, len(edges))
	for predecessor, successor := range edges {
		copyEdges[predecessor] = successor
	}
	return &InMemoryTransitionCache{edges: copyEdges}
}

func (c *InMemoryTransitionCache) GetSuccessor(predecessorDID string) (string, bool) {
	successor, ok := c.edges[predecessorDID]
	return successor, ok
}

func (c *InMemoryTransitionCache) CompareAndSet(predecessorDID string, successorDID string) bool {
	if existing, ok := c.edges[predecessorDID]; ok {
		return existing == successorDID
	}
	c.edges[predecessorDID] = successorDID
	return true
}

var e1SegmentPattern = regexp.MustCompile(`^e1_[A-Za-z0-9_-]{43}$`)

func ParseDidWbaE1(did string) (DidWbaE1Profile, error) {
	parts := strings.Split(did, ":")
	if len(parts) < 5 || parts[0] != "did" || parts[1] != "wba" || !e1SegmentPattern.MatchString(parts[len(parts)-1]) {
		return DidWbaE1Profile{}, newTransitionError(
			TransitionErrorUnsupportedProfile,
			"automatic transition requires a path-based did:wba E1 DID",
		)
	}
	return DidWbaE1Profile{
		DID:               did,
		Origin:            parts[2],
		StableSubjectPath: strings.Join(parts[2:len(parts)-1], ":"),
		Fingerprint:       parts[len(parts)-1][3:],
	}, nil
}

func requireDocumentID(did string, document map[string]any) error {
	if stringValue(document["id"]) != did {
		return newTransitionError(TransitionErrorInvalidDocument, "DID Document id mismatch")
	}
	return nil
}

func bindingMethod(document map[string]any, profile DidWbaE1Profile) map[string]any {
	methods, _ := document["verificationMethod"].([]any)
	for _, rawMethod := range methods {
		method, ok := rawMethod.(map[string]any)
		if !ok {
			continue
		}
		publicKey, err := ExtractPublicKey(method)
		if err != nil {
			continue
		}
		fingerprint, err := ComputeMultikeyFingerprint(publicKey)
		if err == nil && fingerprint == profile.Fingerprint {
			return method
		}
	}
	return nil
}

func VerifyActiveE1Document(did string, document map[string]any) error {
	profile, err := ParseDidWbaE1(did)
	if err != nil {
		return err
	}
	if err := requireDocumentID(did, document); err != nil {
		return err
	}
	if deactivated, _ := document["deactivated"].(bool); deactivated {
		return newTransitionError(TransitionErrorInvalidDocument, "expected an active DID Document")
	}
	proofValue, ok := document["proof"].(map[string]any)
	if !ok {
		return newTransitionError(TransitionErrorInvalidProof, "active E1 proof is required")
	}
	methodID := stringValue(proofValue["verificationMethod"])
	if methodID == "" || !IsAssertionMethodAuthorized(document, methodID) {
		return newTransitionError(TransitionErrorInvalidProof, "binding key is not authorized")
	}
	method := FindVerificationMethod(document, methodID)
	if method == nil {
		return newTransitionError(TransitionErrorInvalidProof, "binding key is missing")
	}
	publicKey, err := ExtractPublicKey(method)
	if err != nil {
		return newTransitionError(TransitionErrorInvalidProof, "invalid binding key")
	}
	fingerprint, err := ComputeMultikeyFingerprint(publicKey)
	if err != nil || fingerprint != profile.Fingerprint {
		return newTransitionError(TransitionErrorInvalidProof, "binding fingerprint mismatch")
	}
	if !proof.VerifyW3CProof(document, publicKey, proof.VerificationOptions{ExpectedPurpose: "assertionMethod"}) {
		return newTransitionError(TransitionErrorInvalidProof, "active E1 proof verification failed")
	}
	return nil
}

func verifyProviderAssertion(
	predecessorDocument map[string]any,
	predecessor DidWbaE1Profile,
	successor DidWbaE1Profile,
	providerFetcher DidDocumentFetcher,
) error {
	assertion, ok := predecessorDocument["providerTransitionAssertion"].(map[string]any)
	if !ok || len(assertion) != 7 {
		return newTransitionError(TransitionErrorInvalidProviderAssertion, "providerTransitionAssertion has an invalid shape")
	}
	for _, field := range []string{"type", "providerDid", "predecessorDid", "successorDid", "stableSubjectPath", "issuedAt", "proof"} {
		if _, exists := assertion[field]; !exists {
			return newTransitionError(TransitionErrorInvalidProviderAssertion, "providerTransitionAssertion has an invalid shape")
		}
	}
	providerDID := "did:wba:" + predecessor.Origin
	issuedAt := stringValue(assertion["issuedAt"])
	parsedTime, timeErr := time.Parse("2006-01-02T15:04:05Z", issuedAt)
	assertionProof, proofOK := assertion["proof"].(map[string]any)
	if stringValue(assertion["type"]) != "DidWbaProviderTransitionAssertion" ||
		stringValue(assertion["providerDid"]) != providerDID ||
		stringValue(assertion["predecessorDid"]) != predecessor.DID ||
		stringValue(assertion["successorDid"]) != successor.DID ||
		stringValue(assertion["stableSubjectPath"]) != predecessor.StableSubjectPath ||
		timeErr != nil || parsedTime.UTC().Format("2006-01-02T15:04:05Z") != issuedAt ||
		!proofOK || stringValue(assertionProof["created"]) != issuedAt {
		return newTransitionError(TransitionErrorInvalidProviderAssertion, "providerTransitionAssertion binding fields are invalid")
	}
	if providerFetcher == nil {
		return newTransitionError(TransitionErrorInvalidProviderAssertion, "provider DID resolver is required")
	}
	providerDocument, err := providerFetcher(providerDID)
	if err != nil {
		return newTransitionError(TransitionErrorNetwork, err.Error())
	}
	if err := requireDocumentID(providerDID, providerDocument); err != nil {
		return err
	}
	methodID := stringValue(assertionProof["verificationMethod"])
	if !strings.HasPrefix(methodID, providerDID+"#") || !IsAssertionMethodAuthorized(providerDocument, methodID) {
		return newTransitionError(TransitionErrorInvalidProviderAssertion, "provider proof key is not authorized")
	}
	method := FindVerificationMethod(providerDocument, methodID)
	if method == nil {
		return newTransitionError(TransitionErrorInvalidProviderAssertion, "provider proof key is missing")
	}
	publicKey, err := ExtractPublicKey(method)
	if err != nil || !proof.VerifyW3CProof(assertion, publicKey, proof.VerificationOptions{ExpectedPurpose: "assertionMethod"}) {
		return newTransitionError(TransitionErrorInvalidProviderAssertion, "providerTransitionAssertion proof verification failed")
	}
	return nil
}

func VerifyTransitionHop(
	predecessorDocument map[string]any,
	successorDocument map[string]any,
	trustedPredecessor map[string]any,
	providerFetcher DidDocumentFetcher,
) (TransitionHop, error) {
	predecessorDID := stringValue(predecessorDocument["id"])
	successorDID := stringValue(predecessorDocument["successorDid"])
	if predecessorDID == "" || successorDID == "" {
		return TransitionHop{}, newTransitionError(TransitionErrorInvalidDocument, "deactivated predecessor requires id and successorDid")
	}
	predecessor, err := ParseDidWbaE1(predecessorDID)
	if err != nil {
		return TransitionHop{}, err
	}
	successor, err := ParseDidWbaE1(successorDID)
	if err != nil {
		return TransitionHop{}, err
	}
	if err := requireDocumentID(successorDID, successorDocument); err != nil {
		return TransitionHop{}, err
	}
	deactivated, _ := predecessorDocument["deactivated"].(bool)
	if !deactivated {
		return TransitionHop{}, newTransitionError(TransitionErrorInvalidDocument, "predecessor is not deactivated")
	}
	if predecessor.StableSubjectPath != successor.StableSubjectPath {
		return TransitionHop{}, newTransitionError(TransitionErrorStablePathMismatch, "predecessor and successor stable subject paths differ")
	}
	binding := bindingMethod(predecessorDocument, predecessor)
	if binding == nil {
		return TransitionHop{}, newTransitionError(TransitionErrorInvalidDocument, "deactivated predecessor does not retain its binding key")
	}
	if aliases, ok := successorDocument["alsoKnownAs"].([]any); ok {
		matching := make([]string, 0)
		for _, rawAlias := range aliases {
			alias, ok := rawAlias.(string)
			if !ok {
				continue
			}
			aliasProfile, parseErr := ParseDidWbaE1(alias)
			if parseErr == nil && aliasProfile.StableSubjectPath == successor.StableSubjectPath {
				matching = append(matching, alias)
			}
		}
		if len(matching) > 0 {
			found := false
			for _, alias := range matching {
				found = found || alias == predecessorDID
			}
			if !found {
				return TransitionHop{}, newTransitionError(TransitionErrorDirectSuccessorRequired, "successor identifies a different direct predecessor")
			}
		}
	}

	_, providerPresent := predecessorDocument["providerTransitionAssertion"]
	if providerPresent {
		if err := verifyProviderAssertion(predecessorDocument, predecessor, successor, providerFetcher); err != nil {
			return TransitionHop{}, err
		}
	}

	assurance := TransitionAssuranceUnverified
	if rawProof, proofPresent := predecessorDocument["proof"]; proofPresent {
		transitionProof, ok := rawProof.(map[string]any)
		if !ok {
			return TransitionHop{}, newTransitionError(TransitionErrorInvalidProof, "transition proof is invalid")
		}
		methodID := stringValue(transitionProof["verificationMethod"])
		if stringValue(binding["id"]) == methodID {
			publicKey, extractErr := ExtractPublicKey(binding)
			if extractErr != nil || !proof.VerifyW3CProof(predecessorDocument, publicKey, proof.VerificationOptions{ExpectedPurpose: "assertionMethod"}) {
				return TransitionHop{}, newTransitionError(TransitionErrorInvalidProof, "old binding proof failed")
			}
			assurance = TransitionAssuranceVerified
		} else {
			trustedMethod := FindVerificationMethod(trustedPredecessor, methodID)
			if trustedPredecessor == nil || trustedMethod == nil || !IsAssertionMethodAuthorized(trustedPredecessor, methodID) {
				return TransitionHop{}, newTransitionError(TransitionErrorRecoveryNotPreauthorized, "recovery key was not pre-authorized by the trusted predecessor")
			}
			publicKey, extractErr := ExtractPublicKey(trustedMethod)
			if extractErr != nil || !proof.VerifyW3CProof(predecessorDocument, publicKey, proof.VerificationOptions{ExpectedPurpose: "assertionMethod"}) {
				return TransitionHop{}, newTransitionError(TransitionErrorInvalidProof, "recovery proof failed")
			}
			assurance = TransitionAssuranceRecoveryVerified
		}
	} else if providerPresent {
		assurance = TransitionAssuranceProviderAsserted
	}
	return TransitionHop{PredecessorDID: predecessorDID, SuccessorDID: successorDID, Assurance: assurance}, nil
}

func assuranceRank(value TransitionAssurance) int {
	switch value {
	case TransitionAssuranceVerified:
		return 0
	case TransitionAssuranceRecoveryVerified:
		return 1
	case TransitionAssuranceProviderAsserted:
		return 2
	default:
		return 3
	}
}

func ResolveCurrentDID(
	requestedDID string,
	fetcher DidDocumentFetcher,
	trustedDocuments map[string]map[string]any,
	providerFetcher DidDocumentFetcher,
	cache TransitionCache,
	maxHops int,
) (TransitionResult, error) {
	if _, err := ParseDidWbaE1(requestedDID); err != nil {
		return TransitionResult{}, err
	}
	if maxHops < 1 {
		return TransitionResult{}, newTransitionError(TransitionErrorMaxHopsExceeded, "maxHops must be positive")
	}
	current := requestedDID
	visited := make(map[string]bool)
	hops := make([]TransitionHop, 0)
	for {
		if visited[current] {
			return TransitionResult{}, newTransitionError(TransitionErrorCycle, "transition chain contains a cycle")
		}
		visited[current] = true
		document, err := fetcher(current)
		if err != nil {
			return TransitionResult{}, newTransitionError(TransitionErrorNetwork, err.Error())
		}
		if err := requireDocumentID(current, document); err != nil {
			return TransitionResult{}, err
		}
		deactivated, _ := document["deactivated"].(bool)
		if !deactivated {
			if err := VerifyActiveE1Document(current, document); err != nil {
				return TransitionResult{}, err
			}
			var assurance *TransitionAssurance
			for _, hop := range hops {
				if assurance == nil || assuranceRank(hop.Assurance) > assuranceRank(*assurance) {
					value := hop.Assurance
					assurance = &value
				}
			}
			status := TransitionStatusActive
			if len(hops) > 0 {
				status = TransitionStatusSuperseded
			}
			return TransitionResult{RequestedDID: requestedDID, CurrentDID: current, Status: status, Assurance: assurance, Hops: hops}, nil
		}
		if len(hops) >= maxHops {
			return TransitionResult{}, newTransitionError(TransitionErrorMaxHopsExceeded, "transition chain exceeds maxHops")
		}
		successorDID := stringValue(document["successorDid"])
		if successorDID == "" {
			return TransitionResult{}, newTransitionError(TransitionErrorInvalidDocument, "deactivated transition document has no successorDid")
		}
		if visited[successorDID] {
			return TransitionResult{}, newTransitionError(TransitionErrorCycle, "transition chain contains a cycle")
		}
		successorDocument, fetchErr := fetcher(successorDID)
		if fetchErr != nil {
			return TransitionResult{}, newTransitionError(TransitionErrorNetwork, fetchErr.Error())
		}
		hop, verifyErr := VerifyTransitionHop(document, successorDocument, trustedDocuments[current], providerFetcher)
		if verifyErr != nil {
			return TransitionResult{}, verifyErr
		}
		if !cache.CompareAndSet(current, successorDID) {
			return TransitionResult{}, newTransitionError(TransitionErrorConflict, "a different successor is already cached for predecessor")
		}
		hops = append(hops, hop)
		current = successorDID
	}
}
