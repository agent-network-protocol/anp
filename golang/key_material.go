package anp

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"math/big"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	secp256k1ecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// KeyType identifies the supported ANP key algorithms.
type KeyType string

const (
	KeyTypeSecp256k1 KeyType = "secp256k1"
	KeyTypeSecp256r1 KeyType = "secp256r1"
	KeyTypeEd25519   KeyType = "ed25519"
	KeyTypeX25519    KeyType = "x25519"
)

const (
	secp256k1PrivateLabel = "ANP SECP256K1 PRIVATE KEY"
	secp256k1PublicLabel  = "ANP SECP256K1 PUBLIC KEY"
	secp256r1PrivateLabel = "ANP SECP256R1 PRIVATE KEY"
	secp256r1PublicLabel  = "ANP SECP256R1 PUBLIC KEY"
	ed25519PrivateLabel   = "ANP ED25519 PRIVATE KEY"
	ed25519PublicLabel    = "ANP ED25519 PUBLIC KEY"
	x25519PrivateLabel    = "ANP X25519 PRIVATE KEY"
	x25519PublicLabel     = "ANP X25519 PUBLIC KEY"
)

// GeneratedKeyPairPEM stores ANP PEM encodings for a generated key pair.
type GeneratedKeyPairPEM struct {
	PrivateKeyPEM string `json:"private_key_pem"`
	PublicKeyPEM  string `json:"public_key_pem"`
}

// KeyMaterialError reports invalid or unsupported key material operations.
type KeyMaterialError struct {
	Message string
}

// Error implements error.
func (e *KeyMaterialError) Error() string {
	return e.Message
}

// PrivateKeyMaterial stores an ANP private key in raw form.
type PrivateKeyMaterial struct {
	Type  KeyType `json:"type"`
	Bytes []byte  `json:"bytes"`
}

// PublicKeyMaterial stores an ANP public key in raw form.
type PublicKeyMaterial struct {
	Type  KeyType `json:"type"`
	Bytes []byte  `json:"bytes"`
}

// GeneratePrivateKeyMaterial generates a new private key for the requested type.
func GeneratePrivateKeyMaterial(keyType KeyType) (PrivateKeyMaterial, error) {
	switch keyType {
	case KeyTypeSecp256k1:
		key, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
		if err != nil {
			return PrivateKeyMaterial{}, err
		}
		return PrivateKeyMaterial{Type: keyType, Bytes: padScalar(key.D.Bytes(), 32)}, nil
	case KeyTypeSecp256r1:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return PrivateKeyMaterial{}, err
		}
		return PrivateKeyMaterial{Type: keyType, Bytes: padScalar(key.D.Bytes(), 32)}, nil
	case KeyTypeEd25519:
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return PrivateKeyMaterial{}, err
		}
		return PrivateKeyMaterial{Type: keyType, Bytes: append([]byte(nil), privateKey.Seed()...)}, nil
	case KeyTypeX25519:
		privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return PrivateKeyMaterial{}, err
		}
		return PrivateKeyMaterial{Type: keyType, Bytes: append([]byte(nil), privateKey.Bytes()...)}, nil
	default:
		return PrivateKeyMaterial{}, &KeyMaterialError{Message: "unsupported key type"}
	}
}

// GenerateKeyPairPEM returns a generated ANP key pair in raw and PEM forms.
func GenerateKeyPairPEM(keyType KeyType) (PrivateKeyMaterial, PublicKeyMaterial, GeneratedKeyPairPEM, error) {
	privateKey, err := GeneratePrivateKeyMaterial(keyType)
	if err != nil {
		return PrivateKeyMaterial{}, PublicKeyMaterial{}, GeneratedKeyPairPEM{}, err
	}
	publicKey, err := privateKey.PublicKey()
	if err != nil {
		return PrivateKeyMaterial{}, PublicKeyMaterial{}, GeneratedKeyPairPEM{}, err
	}
	return privateKey, publicKey, GeneratedKeyPairPEM{
		PrivateKeyPEM: privateKey.ToPEM(),
		PublicKeyPEM:  publicKey.ToPEM(),
	}, nil
}

// PublicKey derives the matching public key.
func (k PrivateKeyMaterial) PublicKey() (PublicKeyMaterial, error) {
	switch k.Type {
	case KeyTypeSecp256k1:
		if len(k.Bytes) != 32 {
			return PublicKeyMaterial{}, &KeyMaterialError{Message: "invalid secp256k1 private key bytes"}
		}
		x, y := btcec.S256().ScalarBaseMult(k.Bytes)
		return PublicKeyMaterial{Type: KeyTypeSecp256k1, Bytes: elliptic.MarshalCompressed(btcec.S256(), x, y)}, nil
	case KeyTypeSecp256r1:
		if len(k.Bytes) != 32 {
			return PublicKeyMaterial{}, &KeyMaterialError{Message: "invalid secp256r1 private key bytes"}
		}
		x, y := elliptic.P256().ScalarBaseMult(k.Bytes)
		return PublicKeyMaterial{Type: KeyTypeSecp256r1, Bytes: elliptic.MarshalCompressed(elliptic.P256(), x, y)}, nil
	case KeyTypeEd25519:
		if len(k.Bytes) != ed25519.SeedSize {
			return PublicKeyMaterial{}, &KeyMaterialError{Message: "invalid ed25519 private key bytes"}
		}
		privateKey := ed25519.NewKeyFromSeed(k.Bytes)
		publicKey := privateKey.Public().(ed25519.PublicKey)
		return PublicKeyMaterial{Type: KeyTypeEd25519, Bytes: append([]byte(nil), publicKey...)}, nil
	case KeyTypeX25519:
		privateKey, err := ecdh.X25519().NewPrivateKey(k.Bytes)
		if err != nil {
			return PublicKeyMaterial{}, err
		}
		return PublicKeyMaterial{Type: KeyTypeX25519, Bytes: append([]byte(nil), privateKey.PublicKey().Bytes()...)}, nil
	default:
		return PublicKeyMaterial{}, &KeyMaterialError{Message: "unsupported key type"}
	}
}

// SignMessage signs a message using ANP's cross-language conventions.
func (k PrivateKeyMaterial) SignMessage(message []byte) ([]byte, error) {
	switch k.Type {
	case KeyTypeSecp256k1:
		privKey, _ := btcec.PrivKeyFromBytes(k.Bytes)
		hash := sha256.Sum256(message)
		compact := secp256k1ecdsa.SignCompact(privKey, hash[:], false)
		if len(compact) != 65 {
			return nil, &KeyMaterialError{Message: "invalid compact signature size"}
		}
		return append([]byte(nil), compact[1:]...), nil
	case KeyTypeSecp256r1:
		privateKey, err := loadP256PrivateKey(k.Bytes)
		if err != nil {
			return nil, err
		}
		hash := sha256.Sum256(message)
		r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
		if err != nil {
			return nil, err
		}
		return marshalP1363Signature(r, s, 32), nil
	case KeyTypeEd25519:
		if len(k.Bytes) != ed25519.SeedSize {
			return nil, &KeyMaterialError{Message: "invalid ed25519 private key bytes"}
		}
		return ed25519.Sign(ed25519.NewKeyFromSeed(k.Bytes), message), nil
	case KeyTypeX25519:
		return nil, &KeyMaterialError{Message: "unsupported key type"}
	default:
		return nil, &KeyMaterialError{Message: "unsupported key type"}
	}
}

// VerifyMessage verifies a signature using ANP's cross-language conventions.
func (k PublicKeyMaterial) VerifyMessage(message []byte, signature []byte) error {
	switch k.Type {
	case KeyTypeSecp256k1:
		publicKey, err := btcec.ParsePubKey(k.Bytes)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(message)
		if len(signature) == 64 {
			expected := publicKey.SerializeCompressed()
			for header := byte(27); header <= byte(34); header++ {
				candidate, _, recoverErr := secp256k1ecdsa.RecoverCompact(append([]byte{header}, signature...), hash[:])
				if recoverErr == nil && candidate != nil && bytesEqual(candidate.SerializeCompressed(), expected) {
					return nil
				}
			}
			return &KeyMaterialError{Message: "invalid signature encoding"}
		}
		sig, err := secp256k1ecdsa.ParseDERSignature(signature)
		if err != nil {
			return &KeyMaterialError{Message: "invalid signature encoding"}
		}
		if !sig.Verify(hash[:], publicKey) {
			return &KeyMaterialError{Message: "invalid signature encoding"}
		}
		return nil
	case KeyTypeSecp256r1:
		publicKey, err := loadP256PublicKey(k.Bytes)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(message)
		if len(signature) == 64 {
			r, s, err := parseP1363Signature(signature, 32)
			if err != nil {
				return err
			}
			if !ecdsa.Verify(publicKey, hash[:], r, s) {
				return &KeyMaterialError{Message: "invalid signature encoding"}
			}
			return nil
		}
		if !ecdsa.VerifyASN1(publicKey, hash[:], signature) {
			return &KeyMaterialError{Message: "invalid signature encoding"}
		}
		return nil
	case KeyTypeEd25519:
		if len(k.Bytes) != ed25519.PublicKeySize {
			return &KeyMaterialError{Message: "invalid ed25519 public key bytes"}
		}
		if !ed25519.Verify(ed25519.PublicKey(k.Bytes), message, signature) {
			return &KeyMaterialError{Message: "invalid signature encoding"}
		}
		return nil
	case KeyTypeX25519:
		return &KeyMaterialError{Message: "verification is not supported for X25519"}
	default:
		return &KeyMaterialError{Message: "unsupported key type"}
	}
}

// ToPEM encodes the private key using ANP PEM labels.
func (k PrivateKeyMaterial) ToPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: privateKeyLabel(k.Type), Bytes: k.Bytes}))
}

// ToPEM encodes the public key using ANP PEM labels.
func (k PublicKeyMaterial) ToPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: publicKeyLabel(k.Type), Bytes: k.Bytes}))
}

// PrivateKeyFromPEM decodes an ANP private key PEM.
func PrivateKeyFromPEM(input string) (PrivateKeyMaterial, error) {
	block, rest := pem.Decode([]byte(input))
	if block == nil || len(rest) > 0 {
		return PrivateKeyMaterial{}, &KeyMaterialError{Message: "invalid PEM structure"}
	}
	keyType, err := keyTypeFromPrivateLabel(block.Type)
	if err != nil {
		return PrivateKeyMaterial{}, err
	}
	return PrivateKeyMaterial{Type: keyType, Bytes: append([]byte(nil), block.Bytes...)}, nil
}

// PublicKeyFromPEM decodes an ANP public key PEM.
func PublicKeyFromPEM(input string) (PublicKeyMaterial, error) {
	block, rest := pem.Decode([]byte(input))
	if block == nil || len(rest) > 0 {
		return PublicKeyMaterial{}, &KeyMaterialError{Message: "invalid PEM structure"}
	}
	keyType, err := keyTypeFromPublicLabel(block.Type)
	if err != nil {
		return PublicKeyMaterial{}, err
	}
	return PublicKeyMaterial{Type: keyType, Bytes: append([]byte(nil), block.Bytes...)}, nil
}

// PublicKeyToJWK converts a public key to JWK fields used by ANP helpers.
func PublicKeyToJWK(publicKey PublicKeyMaterial) (map[string]any, error) {
	switch publicKey.Type {
	case KeyTypeSecp256k1:
		parsed, err := btcec.ParsePubKey(publicKey.Bytes)
		if err != nil {
			return nil, err
		}
		uncompressed := parsed.SerializeUncompressed()
		return map[string]any{
			"kty": "EC",
			"crv": "secp256k1",
			"x":   EncodeBase64URL(uncompressed[1:33]),
			"y":   EncodeBase64URL(uncompressed[33:65]),
		}, nil
	case KeyTypeSecp256r1:
		parsed, err := loadP256PublicKey(publicKey.Bytes)
		if err != nil {
			return nil, err
		}
		uncompressed := elliptic.Marshal(elliptic.P256(), parsed.X, parsed.Y)
		return map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   EncodeBase64URL(uncompressed[1:33]),
			"y":   EncodeBase64URL(uncompressed[33:65]),
		}, nil
	case KeyTypeEd25519:
		return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": EncodeBase64URL(publicKey.Bytes)}, nil
	case KeyTypeX25519:
		return map[string]any{"kty": "OKP", "crv": "X25519", "x": EncodeBase64URL(publicKey.Bytes)}, nil
	default:
		return nil, &KeyMaterialError{Message: "unsupported public key type"}
	}
}

// PublicKeyFromJWK converts JWK fields to ANP public key material.
func PublicKeyFromJWK(jwk map[string]any) (PublicKeyMaterial, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	x, _ := jwk["x"].(string)
	y, _ := jwk["y"].(string)
	switch {
	case kty == "EC" && crv == "secp256k1":
		xBytes, err := DecodeBase64URL(x)
		if err != nil {
			return PublicKeyMaterial{}, err
		}
		yBytes, err := DecodeBase64URL(y)
		if err != nil {
			return PublicKeyMaterial{}, err
		}
		uncompressed := append([]byte{0x04}, append(append([]byte(nil), xBytes...), yBytes...)...)
		parsed, err := btcec.ParsePubKey(uncompressed)
		if err != nil {
			return PublicKeyMaterial{}, err
		}
		return PublicKeyMaterial{Type: KeyTypeSecp256k1, Bytes: parsed.SerializeCompressed()}, nil
	case kty == "EC" && crv == "P-256":
		xBytes, err := DecodeBase64URL(x)
		if err != nil {
			return PublicKeyMaterial{}, err
		}
		yBytes, err := DecodeBase64URL(y)
		if err != nil {
			return PublicKeyMaterial{}, err
		}
		uncompressed := append([]byte{0x04}, append(append([]byte(nil), xBytes...), yBytes...)...)
		parsedX, parsedY := elliptic.Unmarshal(elliptic.P256(), uncompressed)
		if parsedX == nil || parsedY == nil {
			return PublicKeyMaterial{}, &KeyMaterialError{Message: "invalid key bytes"}
		}
		return PublicKeyMaterial{Type: KeyTypeSecp256r1, Bytes: elliptic.MarshalCompressed(elliptic.P256(), parsedX, parsedY)}, nil
	case kty == "OKP" && crv == "Ed25519":
		bytes, err := DecodeBase64URL(x)
		if err != nil {
			return PublicKeyMaterial{}, err
		}
		if len(bytes) != ed25519.PublicKeySize {
			return PublicKeyMaterial{}, &KeyMaterialError{Message: "invalid key bytes"}
		}
		return PublicKeyMaterial{Type: KeyTypeEd25519, Bytes: bytes}, nil
	case kty == "OKP" && crv == "X25519":
		bytes, err := DecodeBase64URL(x)
		if err != nil {
			return PublicKeyMaterial{}, err
		}
		if len(bytes) != 32 {
			return PublicKeyMaterial{}, &KeyMaterialError{Message: "invalid key bytes"}
		}
		return PublicKeyMaterial{Type: KeyTypeX25519, Bytes: bytes}, nil
	default:
		return PublicKeyMaterial{}, &KeyMaterialError{Message: "unsupported key type"}
	}
}

func privateKeyLabel(keyType KeyType) string {
	switch keyType {
	case KeyTypeSecp256k1:
		return secp256k1PrivateLabel
	case KeyTypeSecp256r1:
		return secp256r1PrivateLabel
	case KeyTypeEd25519:
		return ed25519PrivateLabel
	case KeyTypeX25519:
		return x25519PrivateLabel
	default:
		return ""
	}
}

func publicKeyLabel(keyType KeyType) string {
	switch keyType {
	case KeyTypeSecp256k1:
		return secp256k1PublicLabel
	case KeyTypeSecp256r1:
		return secp256r1PublicLabel
	case KeyTypeEd25519:
		return ed25519PublicLabel
	case KeyTypeX25519:
		return x25519PublicLabel
	default:
		return ""
	}
}

func keyTypeFromPrivateLabel(label string) (KeyType, error) {
	switch label {
	case secp256k1PrivateLabel:
		return KeyTypeSecp256k1, nil
	case secp256r1PrivateLabel:
		return KeyTypeSecp256r1, nil
	case ed25519PrivateLabel:
		return KeyTypeEd25519, nil
	case x25519PrivateLabel:
		return KeyTypeX25519, nil
	default:
		return "", &KeyMaterialError{Message: fmt.Sprintf("invalid PEM label: %s", label)}
	}
}

func keyTypeFromPublicLabel(label string) (KeyType, error) {
	switch label {
	case secp256k1PublicLabel:
		return KeyTypeSecp256k1, nil
	case secp256r1PublicLabel:
		return KeyTypeSecp256r1, nil
	case ed25519PublicLabel:
		return KeyTypeEd25519, nil
	case x25519PublicLabel:
		return KeyTypeX25519, nil
	default:
		return "", &KeyMaterialError{Message: fmt.Sprintf("invalid PEM label: %s", label)}
	}
}

func loadP256PrivateKey(raw []byte) (*ecdsa.PrivateKey, error) {
	if len(raw) != 32 {
		return nil, &KeyMaterialError{Message: "invalid secp256r1 private key bytes"}
	}
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult(raw)
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: new(big.Int).SetBytes(raw)}, nil
}

func loadP256PublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	curve := elliptic.P256()
	x, y := elliptic.UnmarshalCompressed(curve, raw)
	if x == nil || y == nil {
		x, y = elliptic.Unmarshal(curve, raw)
	}
	if x == nil || y == nil {
		return nil, &KeyMaterialError{Message: "invalid secp256r1 public key bytes"}
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func parseP1363Signature(signature []byte, size int) (*big.Int, *big.Int, error) {
	if len(signature) != size*2 {
		return nil, nil, &KeyMaterialError{Message: "invalid signature encoding"}
	}
	return new(big.Int).SetBytes(signature[:size]), new(big.Int).SetBytes(signature[size:]), nil
}

func marshalP1363Signature(r, s *big.Int, size int) []byte {
	encoded := make([]byte, size*2)
	copy(encoded[size-len(r.Bytes()):size], r.Bytes())
	copy(encoded[2*size-len(s.Bytes()):], s.Bytes())
	return encoded
}

func padScalar(raw []byte, size int) []byte {
	result := make([]byte, size)
	copy(result[size-len(raw):], raw)
	return result
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
