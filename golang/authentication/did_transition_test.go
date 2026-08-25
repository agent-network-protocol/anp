package authentication

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type transitionManifest struct {
	VectorFile   string `json:"vectorFile"`
	VectorSHA256 string `json:"vectorSha256"`
	CaseCount    int    `json:"caseCount"`
}

type transitionVectorSuite struct {
	Cases []transitionVectorCase `json:"cases"`
}

type transitionVectorCase struct {
	ID                       string            `json:"id"`
	Operation                string            `json:"operation"`
	RequestedDID             string            `json:"requestedDid"`
	TrustedDocuments         map[string]string `json:"trustedDocuments"`
	ResolvedDocuments        map[string]string `json:"resolvedDocuments"`
	PreludeResolvedDocuments map[string]string `json:"preludeResolvedDocuments"`
	ProviderDocuments        map[string]string `json:"providerDocuments"`
	CacheEdges               map[string]string `json:"cacheEdges"`
	ExpectedCacheEdges       map[string]string `json:"expectedCacheEdges"`
	UntrustedCurrentDIDHint  string            `json:"untrustedCurrentDidHint"`
	MaxHops                  int               `json:"maxHops"`
	Expected                 map[string]any    `json:"expected"`
}

func loadTransitionJSON(t *testing.T, path string, target any) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(contents, target); err != nil {
		t.Fatal(err)
	}
	return contents
}

func loadTransitionDocuments(t *testing.T, root string, paths map[string]string) map[string]map[string]any {
	t.Helper()
	documents := make(map[string]map[string]any, len(paths))
	for did, path := range paths {
		var document map[string]any
		loadTransitionJSON(t, filepath.Join(root, path), &document)
		documents[did] = document
	}
	return documents
}

func TestDidTransitionSharedVectors(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "did_transition")
	var manifest transitionManifest
	loadTransitionJSON(t, filepath.Join(root, "manifest.json"), &manifest)
	var suite transitionVectorSuite
	vectorBytes := loadTransitionJSON(t, filepath.Join(root, manifest.VectorFile), &suite)
	digest := sha256.Sum256(vectorBytes)
	if hex.EncodeToString(digest[:]) != manifest.VectorSHA256 {
		t.Fatal("transition vector digest does not match manifest")
	}
	if len(suite.Cases) != manifest.CaseCount {
		t.Fatalf("case count = %d, want %d", len(suite.Cases), manifest.CaseCount)
	}

	for _, vector := range suite.Cases {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			resolved := loadTransitionDocuments(t, root, vector.ResolvedDocuments)
			preludeResolved := loadTransitionDocuments(t, root, vector.PreludeResolvedDocuments)
			trusted := loadTransitionDocuments(t, root, vector.TrustedDocuments)
			providers := loadTransitionDocuments(t, root, vector.ProviderDocuments)
			fetcher := func(did string) (map[string]any, error) {
				document, ok := resolved[did]
				if !ok {
					return nil, errors.New("resolved document not found")
				}
				return document, nil
			}
			providerFetcher := func(did string) (map[string]any, error) {
				document, ok := providers[did]
				if !ok {
					return nil, errors.New("provider document not found")
				}
				return document, nil
			}

			var actual map[string]any
			var err error
			cache := NewInMemoryTransitionCache(vector.CacheEdges)
			switch vector.Operation {
			case "parse":
				_, err = ParseDidWbaE1(vector.RequestedDID)
			case "verify_active":
				err = VerifyActiveE1Document(vector.RequestedDID, resolved[vector.RequestedDID])
				if err == nil {
					actual = map[string]any{
						"status": "active", "currentDid": vector.RequestedDID,
						"hops": []any{}, "assurance": nil,
					}
				}
			case "resolve", "resolve_ignoring_hint", "resolve_after_unverified":
				if vector.Operation == "resolve_ignoring_hint" && vector.UntrustedCurrentDIDHint == "" {
					t.Fatal("resolve_ignoring_hint requires an untrustedCurrentDidHint fixture")
				}
				if vector.Operation == "resolve_after_unverified" {
					preludeFetcher := func(did string) (map[string]any, error) {
						document, ok := preludeResolved[did]
						if !ok {
							return nil, errors.New("prelude document not found")
						}
						return document, nil
					}
					preludeResult, preludeErr := ResolveCurrentDID(
						vector.RequestedDID, preludeFetcher, trusted, nil, cache, vector.MaxHops,
					)
					if preludeErr != nil || preludeResult.Assurance == nil || *preludeResult.Assurance != TransitionAssuranceUnverified {
						t.Fatalf("unverified prelude failed: result=%#v err=%v", preludeResult, preludeErr)
					}
					cacheJSON, _ := json.Marshal(cache.Snapshot())
					initialCacheJSON, _ := json.Marshal(vector.CacheEdges)
					if string(cacheJSON) != string(initialCacheJSON) {
						t.Fatalf("unverified prelude changed cache: %s, want %s", cacheJSON, initialCacheJSON)
					}
				}
				var result TransitionResult
				result, err = ResolveCurrentDID(
					vector.RequestedDID,
					fetcher,
					trusted,
					providerFetcher,
					cache,
					vector.MaxHops,
				)
				if err == nil {
					hops := make([]any, len(result.Hops))
					for index, hop := range result.Hops {
						hops[index] = string(hop.Assurance)
					}
					var assurance any
					if result.Assurance != nil {
						assurance = string(*result.Assurance)
					}
					actual = map[string]any{
						"status": string(result.Status), "currentDid": result.CurrentDID,
						"hops": hops, "assurance": assurance,
					}
				}
			default:
				t.Fatalf("unknown operation %q", vector.Operation)
			}

			if err != nil {
				transitionErr, ok := err.(*DidTransitionError)
				if !ok {
					t.Fatalf("unexpected error type %T: %v", err, err)
				}
				actual = map[string]any{"error": string(transitionErr.Kind), "code": float64(transitionErr.Code)}
			}
			actualJSON, _ := json.Marshal(actual)
			expectedJSON, _ := json.Marshal(vector.Expected)
			if string(actualJSON) != string(expectedJSON) {
				t.Fatalf("actual %s, want %s", actualJSON, expectedJSON)
			}
			cacheJSON, _ := json.Marshal(cache.Snapshot())
			expectedCacheJSON, _ := json.Marshal(vector.ExpectedCacheEdges)
			if (vector.Operation == "resolve" || vector.Operation == "resolve_ignoring_hint" || vector.Operation == "resolve_after_unverified") && string(cacheJSON) != string(expectedCacheJSON) {
				t.Fatalf("cache %s, want %s", cacheJSON, expectedCacheJSON)
			}
		})
	}
}

func TestResolveCurrentDIDAllowsNilCache(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "did_transition")
	var document map[string]any
	loadTransitionJSON(t, filepath.Join(root, "documents", "new-active.json"), &document)
	did := stringValue(document["id"])
	result, err := ResolveCurrentDID(
		did,
		func(string) (map[string]any, error) { return document, nil },
		nil,
		nil,
		nil,
		DefaultMaxTransitionHops,
	)
	if err != nil || result.Status != TransitionStatusActive {
		t.Fatalf("nil cache resolution failed: result=%#v err=%v", result, err)
	}
}
