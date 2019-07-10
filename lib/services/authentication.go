/*
Copyright 2017 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package services

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/pquerna/otp/totp"
	"github.com/tstranex/u2f"
)

// AuthPreference defines the authentication preferences for a specific
// cluster. It defines the type (local, oidc) and second factor (off, otp, oidc).
// AuthPreference is a configuration resource, never create more than one instance
// of it.
type AuthPreference interface {
	// Expiry returns object expiry setting
	Expiry() time.Time
	// SetExpiry sets object expiry
	SetExpiry(time.Time)

	// GetResourceID returns resource ID
	GetResourceID() int64
	// SetResourceID sets resource ID
	SetResourceID(int64)

	// GetType gets the type of authentication: local, saml, or oidc.
	GetType() string
	// SetType sets the type of authentication: local, saml, or oidc.
	SetType(string)

	// GetSecondFactor gets the type of second factor: off, otp or u2f.
	GetSecondFactor() string
	// SetSecondFactor sets the type of second factor: off, otp, or u2f.
	SetSecondFactor(string)

	// GetConnectorName gets the name of the OIDC or SAML connector to use. If
	// this value is empty, we fall back to the first connector in the backend.
	GetConnectorName() string
	// GetConnectorName sets the name of the OIDC or SAML connector to use. If
	// this value is empty, we fall back to the first connector in the backend.
	SetConnectorName(string)

	// GetU2F gets the U2F configuration settings.
	GetU2F() (*U2F, error)
	// SetU2F sets the U2F configuration settings.
	SetU2F(*U2F)

	// CheckAndSetDefaults sets and default values and then
	// verifies the constraints for AuthPreference.
	CheckAndSetDefaults() error

	// String represents a human readable version of authentication settings.
	String() string
}

// NewAuthPreference is a convenience method to to create AuthPreferenceV2.
func NewAuthPreference(spec AuthPreferenceSpecV2) (AuthPreference, error) {
	return &AuthPreferenceV2{
		Kind:    KindClusterAuthPreference,
		Version: V2,
		Metadata: Metadata{
			Name:      MetaNameClusterAuthPreference,
			Namespace: defaults.Namespace,
		},
		Spec: spec,
	}, nil
}

// AuthPreferenceV2 implements AuthPreference.
type AuthPreferenceV2 struct {
	// Kind is a resource kind - always resource.
	Kind string `json:"kind"`

	// SubKind is a resource sub kind
	SubKind string `json:"sub_kind,omitempty"`

	// Version is a resource version.
	Version string `json:"version"`

	// Metadata is metadata about the resource.
	Metadata Metadata `json:"metadata"`

	// Spec is the specification of the resource.
	Spec AuthPreferenceSpecV2 `json:"spec"`
}

// SetExpiry sets expiry time for the object
func (s *AuthPreferenceV2) SetExpiry(expires time.Time) {
	s.Metadata.SetExpiry(expires)
}

// Expirey returns object expiry setting
func (s *AuthPreferenceV2) Expiry() time.Time {
	return s.Metadata.Expiry()
}

// GetResourceID returns resource ID
func (c *AuthPreferenceV2) GetResourceID() int64 {
	return c.Metadata.ID
}

// SetResourceID sets resource ID
func (c *AuthPreferenceV2) SetResourceID(id int64) {
	c.Metadata.ID = id
}

// GetKind returns resource kind
func (c *AuthPreferenceV2) GetKind() string {
	return c.Kind
}

// GetSubKind returns resource subkind
func (c *AuthPreferenceV2) GetSubKind() string {
	return c.SubKind
}

// SetSubKind sets resource subkind
func (c *AuthPreferenceV2) SetSubKind(sk string) {
	c.SubKind = sk
}

// GetType returns the type of authentication.
func (c *AuthPreferenceV2) GetType() string {
	return c.Spec.Type
}

// SetType sets the type of authentication.
func (c *AuthPreferenceV2) SetType(s string) {
	c.Spec.Type = s
}

// GetSecondFactor returns the type of second factor.
func (c *AuthPreferenceV2) GetSecondFactor() string {
	return c.Spec.SecondFactor
}

// SetSecondFactor sets the type of second factor.
func (c *AuthPreferenceV2) SetSecondFactor(s string) {
	c.Spec.SecondFactor = s
}

// GetConnectorName gets the name of the OIDC or SAML connector to use. If
// this value is empty, we fall back to the first connector in the backend.
func (c *AuthPreferenceV2) GetConnectorName() string {
	return c.Spec.ConnectorName
}

// GetConnectorName sets the name of the OIDC or SAML connector to use. If
// this value is empty, we fall back to the first connector in the backend.
func (c *AuthPreferenceV2) SetConnectorName(cn string) {
	c.Spec.ConnectorName = cn
}

// GetU2F gets the U2F configuration settings.
func (c *AuthPreferenceV2) GetU2F() (*U2F, error) {
	if c.Spec.U2F == nil {
		return nil, trace.NotFound("U2F configuration not found")
	}
	return c.Spec.U2F, nil
}

// SetU2F sets the U2F configuration settings.
func (c *AuthPreferenceV2) SetU2F(u2f *U2F) {
	c.Spec.U2F = u2f
}

// CheckAndSetDefaults verifies the constraints for AuthPreference.
func (c *AuthPreferenceV2) CheckAndSetDefaults() error {
	// if nothing is passed in, set defaults
	if c.Spec.Type == "" {
		c.Spec.Type = teleport.Local
	}
	if c.Spec.SecondFactor == "" {
		c.Spec.SecondFactor = teleport.OTP
	}

	// make sure type makes sense
	switch c.Spec.Type {
	case teleport.Local, teleport.OIDC, teleport.SAML, teleport.Github:
	default:
		return trace.BadParameter("authentication type %q not supported", c.Spec.Type)
	}

	// make sure second factor makes sense
	switch c.Spec.SecondFactor {
	case teleport.OFF, teleport.OTP, teleport.U2F:
	default:
		return trace.BadParameter("second factor type %q not supported", c.Spec.SecondFactor)
	}

	return nil
}

// String represents a human readable version of authentication settings.
func (c *AuthPreferenceV2) String() string {
	return fmt.Sprintf("AuthPreference(Type=%q,SecondFactor=%q)", c.Spec.Type, c.Spec.SecondFactor)
}

// AuthPreferenceSpecV2 is the actual data we care about for AuthPreferenceV2.
type AuthPreferenceSpecV2 struct {
	// Type is the type of authentication.
	Type string `json:"type"`

	// SecondFactor is the type of second factor.
	SecondFactor string `json:"second_factor,omitempty"`

	// ConnectorName is the name of the OIDC or SAML connector. If this value is
	// not set the first connector in the backend will be used.
	ConnectorName string `json:"connector_name,omitempty"`

	// U2F are the settings for the U2F device.
	U2F *U2F `json:"u2f,omitempty"`
}

// U2F defines settings for U2F device.
type U2F struct {
	// AppID returns the application ID for universal second factor.
	AppID string `json:"app_id,omitempty"`

	// Facets returns the facets for universal second factor.
	Facets []string `json:"facets,omitempty"`
}

const AuthPreferenceSpecSchemaTemplate = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
	"type": {
		"type": "string"
	},
	"second_factor": {
		"type": "string"
	},
	"connector_name": {
		"type": "string"
	},
	"u2f": {
		"type": "object",
        "additionalProperties": false,
		"properties": {
			"app_id": {
				"type": "string"
			},
			"facets": {
				"type": "array",
				"items": {
					"type": "string"
				}
			}
		}
	}%v
  }
}`

// GetAuthPreferenceSchema returns the schema with optionally injected
// schema for extensions.
func GetAuthPreferenceSchema(extensionSchema string) string {
	var authPreferenceSchema string
	if authPreferenceSchema == "" {
		authPreferenceSchema = fmt.Sprintf(AuthPreferenceSpecSchemaTemplate, "")
	} else {
		authPreferenceSchema = fmt.Sprintf(AuthPreferenceSpecSchemaTemplate, ","+extensionSchema)
	}
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, authPreferenceSchema, DefaultDefinitions)
}

// AuthPreferenceMarshaler implements marshal/unmarshal of AuthPreference implementations
// mostly adds support for extended versions.
type AuthPreferenceMarshaler interface {
	Marshal(c AuthPreference, opts ...MarshalOption) ([]byte, error)
	Unmarshal(bytes []byte, opts ...MarshalOption) (AuthPreference, error)
}

var authPreferenceMarshaler AuthPreferenceMarshaler = &TeleportAuthPreferenceMarshaler{}

func SetAuthPreferenceMarshaler(m AuthPreferenceMarshaler) {
	marshalerMutex.Lock()
	defer marshalerMutex.Unlock()
	authPreferenceMarshaler = m
}

func GetAuthPreferenceMarshaler() AuthPreferenceMarshaler {
	marshalerMutex.Lock()
	defer marshalerMutex.Unlock()
	return authPreferenceMarshaler
}

type TeleportAuthPreferenceMarshaler struct{}

// Unmarshal unmarshals role from JSON or YAML.
func (t *TeleportAuthPreferenceMarshaler) Unmarshal(bytes []byte, opts ...MarshalOption) (AuthPreference, error) {
	var authPreference AuthPreferenceV2

	if len(bytes) == 0 {
		return nil, trace.BadParameter("missing resource data")
	}

	cfg, err := collectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if cfg.SkipValidation {
		if err := utils.FastUnmarshal(bytes, &authPreference); err != nil {
			return nil, trace.BadParameter(err.Error())
		}
	} else {
		err := utils.UnmarshalWithSchema(GetAuthPreferenceSchema(""), &authPreference, bytes)
		if err != nil {
			return nil, trace.BadParameter(err.Error())
		}
	}
	if cfg.ID != 0 {
		authPreference.SetResourceID(cfg.ID)
	}
	if !cfg.Expires.IsZero() {
		authPreference.SetExpiry(cfg.Expires)
	}
	return &authPreference, nil
}

// Marshal marshals role to JSON or YAML.
func (t *TeleportAuthPreferenceMarshaler) Marshal(c AuthPreference, opts ...MarshalOption) ([]byte, error) {
	return json.Marshal(c)
}

// OTPVerifier is a one time password verifier for a specific user.
type OTPVerifier interface {
	// Resource sets common resource properties
	Resource
	// GetUser gets the username assocaited with this verifier
	GetUser() string
	// GetOTPKey gets the secret key associated with this verifier
	GetOTPKey() string
	// Check checks if all passed parameters are valid
	Check() error
	// CheckAndSetDefaults checks and sets default values for any missing fields.
	CheckAndSetDefaults() error
}

// NewOTPVerifier creates a new OTPVerifier resource.
//
// NOTE: This function always creates OTPVerifiers of subkind `teleport.TOTP`
// since all other OTP subkinds are deprecated
func NewOTPVerifier(user string, key string) OTPVerifier {
	return &OTPVerifierV1{
		Kind:    KindOTPVerifier,
		Version: V1,
		SubKind: teleport.TOTP,
		Metadata: Metadata{
			Name:      user,
			Namespace: defaults.Namespace,
		},
		Spec: OTPVerifierSpecV1{
			OTPKey: key,
		},
	}
}

// GetUser gets the username assocaited with this verifier
func (o *OTPVerifierV1) GetUser() string {
	return o.Metadata.Name
}

// GetOTPKey gets the secret key associated with this verifier
func (o *OTPVerifierV1) GetOTPKey() string {
	return o.Spec.OTPKey
}

// Check checks if all passed parameters are valid
func (o *OTPVerifierV1) Check() error {
	if o.GetUser() == "" {
		return trace.BadParameter("missing user name")
	}
	switch kind := o.GetSubKind(); kind {
	case teleport.TOTP:
		_, err := totp.GenerateCode(o.GetOTPKey(), time.Time{})
		if err != nil {
			return trace.BadParameter("invalid TOTP key")
		}
	case teleport.HOTP:
		return trace.BadParameter("hash-based OTP has been deprecated")
	default:
		return trace.BadParameter("unsupported OTP kind %v", kind)
	}
	return nil
}

// CheckAndSetDefaults checks and sets default values for any missing fields.
func (o *OTPVerifierV1) CheckAndSetDefaults() error {
	if err := o.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	// Assume subkind of TOTP if unset
	if o.GetSubKind() == "" {
		o.SetSubKind(teleport.TOTP)
	}
	if err := o.Check(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// GetKind returns resource kind
func (o *OTPVerifierV1) GetKind() string {
	return o.Kind
}

// GetSubKind returns resource subkind
func (o *OTPVerifierV1) GetSubKind() string {
	return o.SubKind
}

// SetSubKind sets resource subkind
func (o *OTPVerifierV1) SetSubKind(subkind string) {
	o.SubKind = subkind
}

// GetVersion returns resource version
func (o *OTPVerifierV1) GetVersion() string {
	return o.Version
}

// GetName returns the name of the resource
func (o *OTPVerifierV1) GetName() string {
	return o.Metadata.GetName()
}

// SetName sets the name of the resource
func (o *OTPVerifierV1) SetName(name string) {
	o.Metadata.SetName(name)
}

// Expiry returns object expiry setting
func (o *OTPVerifierV1) Expiry() time.Time {
	return o.Metadata.Expiry()
}

// SetExpiry sets object expiry
func (o *OTPVerifierV1) SetExpiry(expiry time.Time) {
	o.Metadata.SetExpiry(expiry)
}

// SetTTL sets Expires header using current clock
func (o *OTPVerifierV1) SetTTL(clock clockwork.Clock, ttl time.Duration) {
	o.Metadata.SetTTL(clock, ttl)
}

// GetMetadata returns object metadata
func (o *OTPVerifierV1) GetMetadata() Metadata {
	return o.Metadata.GetMetadata()
}

// GetResourceID returns resource ID
func (o *OTPVerifierV1) GetResourceID() int64 {
	return o.Metadata.GetID()
}

// SetResourceID sets resource ID
func (o *OTPVerifierV1) SetResourceID(id int64) {
	o.Metadata.SetID(id)
}

// String returns human readable version of OTPVerifierV1
func (o *OTPVerifierV1) String() string {
	return fmt.Sprintf("OTPVerifier(user=%v)", o.GetUser())
}

// OTPVerifierMarshaler implements marshal/unmarshal of OTPVerifier implementations.
type OTPVerifierMarshaler interface {
	Marshal(OTPVerifier, ...MarshalOption) ([]byte, error)
	Unmarshal([]byte, ...MarshalOption) (OTPVerifier, error)
}

func GetOTPVerifierMarshaler() OTPVerifierMarshaler {
	return &otpVerifierMarshaler{}
}

type otpVerifierMarshaler struct{}

func (_ *otpVerifierMarshaler) Marshal(verifier OTPVerifier, opts ...MarshalOption) ([]byte, error) {
	cfg, err := collectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch v := verifier.(type) {
	case *OTPVerifierV1:
		if !cfg.PreserveResourceID {
			// avoid modifying original object
			cp := *v
			cp.SetResourceID(0)
			v = &cp
		}
		bytes, err := utils.FastMarshal(v)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return bytes, nil
	default:
		return nil, trace.NotImplemented("unknown otp verifier type %T", verifier)
	}
}

func (_ *otpVerifierMarshaler) Unmarshal(bytes []byte, opts ...MarshalOption) (OTPVerifier, error) {
	var verifier OTPVerifierV1

	if len(bytes) == 0 {
		return nil, trace.BadParameter("missing resource data")
	}

	cfg, err := collectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if cfg.SkipValidation {
		if err := utils.FastUnmarshal(bytes, &verifier); err != nil {
			return nil, trace.BadParameter(err.Error())
		}
	} else {
		err := utils.UnmarshalWithSchema(GetOTPVerifierSchema(), &verifier, bytes)
		if err != nil {
			return nil, trace.BadParameter(err.Error())
		}
	}
	if cfg.ID != 0 {
		verifier.SetResourceID(cfg.ID)
	}
	if !cfg.Expires.IsZero() {
		verifier.SetExpiry(cfg.Expires)
	}
	return &verifier, nil
}

// GetOTPVerifierSchema returns JSON schema for one time password verifier resource.
func GetOTPVerifierSchema() string {
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, OTPVerifierSpecSchemaV1, DefaultDefinitions)
}

// OTPVerifierSpecSchemaV1 is a JSON schema for one time password verifier spec.
const OTPVerifierSpecSchemaV1 = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["otp_key"],
  "properties": {
    "otp_key": {"type": "string"}
  }
}`

// U2FRegistration is a universal second factor auth registration for a specific user.
type U2FRegistration interface {
	// Resource sets common resource properties
	Resource
	// GetUser gets the username assocaited with this registration
	GetUser() string
	// GetRawRegistration gets the raw u2f registration data
	GetRawRegistration() []byte
	// GetKeyHandle gets the u2f key idenification handle
	GetKeyHandle() []byte
	// GetPubKeyDER gets the DER encoded public key associated with this registration
	GetPubKeyDER() []byte
	// GetPubKeyECDSA gets the public key as an `ecdsa.PublicKey`.
	GetPubKeyECDSA() (*ecdsa.PublicKey, error)
	// Check checks the provided parameters
	Check() error
	// CheckAndSetDefaults checks and sets default values for any missing fields
	CheckAndSetDefaults() error
}

func TransposeU2FRegistration(user string, r u2f.Registration) (U2FRegistration, error) {
	pubKeyDer, err := x509.MarshalPKIXPublicKey(&r.PubKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	reg := NewU2FRegistration(user, r.Raw, r.KeyHandle, pubKeyDer)
	if err := reg.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	return reg, nil
}

// NewU2FRegistration creates a new U2FRegistration resource.
//
func NewU2FRegistration(user string, raw, keyHandle, pubKey []byte) U2FRegistration {
	return &U2FRegistrationV1{
		Kind:    KindU2FRegistration,
		Version: V1,
		Metadata: Metadata{
			Name:      user,
			Namespace: defaults.Namespace,
		},
		Spec: U2FRegistrationSpecV1{
			Raw:       raw,
			KeyHandle: keyHandle,
			PubKey:    pubKey,
		},
	}
}

// GetUser gets the username assocaited with this registration
func (r *U2FRegistrationV1) GetUser() string {
	return r.Metadata.Name
}

// GetRawRegistration gets the raw u2f registration data
func (r *U2FRegistrationV1) GetRawRegistration() []byte {
	return r.Spec.Raw
}

// GetKeyHandle gets the u2f key idenification handle
func (r *U2FRegistrationV1) GetKeyHandle() []byte {
	return r.Spec.KeyHandle
}

// GetPubKeyDER gets the DER encoded public key associated with this registration
func (r *U2FRegistrationV1) GetPubKeyDER() []byte {
	return r.Spec.PubKey
}

// GetPubKeyECDSA gets the public key as an `ecdsa.PublicKey`.
func (r *U2FRegistrationV1) GetPubKeyECDSA() (*ecdsa.PublicKey, error) {
	pubKeyI, err := x509.ParsePKIXPublicKey(r.GetPubKeyDER())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	pubKey, ok := pubKeyI.(*ecdsa.PublicKey)
	if !ok {
		return nil, trace.Errorf("expected *ecdsa.PublicKey, got %T", pubKeyI)
	}
	return pubKey, nil
}

// Check checks if all passed parameters are valid
func (r *U2FRegistrationV1) Check() error {
	if r.GetUser() == "" {
		return trace.BadParameter("missing user name")
	}
	if len(r.GetKeyHandle()) < 1 {
		return trace.BadParameter("missing u2f key handle")
	}
	if len(r.GetPubKeyDER()) < 1 {
		return trace.BadParameter("missing u2f pubkey")
	}
	if r.Kind != KindU2FRegistration {
		return trace.BadParameter("expected kind %q, got %q", KindU2FRegistration, r.Kind)
	}
	if _, err := r.GetPubKeyECDSA(); err != nil {
		return trace.Wrap(err, "bad u2f pubkey")
	}
	return nil
}

// CheckAndSetDefaults checks and sets default values for any missing fields.
func (r *U2FRegistrationV1) CheckAndSetDefaults() error {
	if err := r.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	if err := r.Check(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// GetKind returns resource kind
func (r *U2FRegistrationV1) GetKind() string {
	return r.Kind
}

// GetSubKind returns resource subkind
func (r *U2FRegistrationV1) GetSubKind() string {
	return r.SubKind
}

// SetSubKind sets resource subkind
func (r *U2FRegistrationV1) SetSubKind(subkind string) {
	r.SubKind = subkind
}

// GetVersion returns resource version
func (r *U2FRegistrationV1) GetVersion() string {
	return r.Version
}

// GetName returns the name of the resource
func (r *U2FRegistrationV1) GetName() string {
	return r.Metadata.GetName()
}

// SetName sets the name of the resource
func (r *U2FRegistrationV1) SetName(name string) {
	r.Metadata.SetName(name)
}

// Expiry returns object expiry setting
func (r *U2FRegistrationV1) Expiry() time.Time {
	return r.Metadata.Expiry()
}

// SetExpiry sets object expiry
func (r *U2FRegistrationV1) SetExpiry(expiry time.Time) {
	r.Metadata.SetExpiry(expiry)
}

// SetTTL sets Expires header using current clock
func (r *U2FRegistrationV1) SetTTL(clock clockwork.Clock, ttl time.Duration) {
	r.Metadata.SetTTL(clock, ttl)
}

// GetMetadata returns object metadata
func (r *U2FRegistrationV1) GetMetadata() Metadata {
	return r.Metadata.GetMetadata()
}

// GetResourceID returns resource ID
func (r *U2FRegistrationV1) GetResourceID() int64 {
	return r.Metadata.GetID()
}

// SetResourceID sets resource ID
func (r *U2FRegistrationV1) SetResourceID(id int64) {
	r.Metadata.SetID(id)
}

// String returns human readable version of U2FRegistrationV1
func (r *U2FRegistrationV1) String() string {
	return fmt.Sprintf("U2FRegistration(user=%v)", r.GetUser())
}

// U2FRegistrationMarshaler implements marshal/unmarshal of U2FRegistration implementations.
type U2FRegistrationMarshaler interface {
	Marshal(U2FRegistration, ...MarshalOption) ([]byte, error)
	Unmarshal([]byte, ...MarshalOption) (U2FRegistration, error)
}

func GetU2FRegistrationMarshaler() U2FRegistrationMarshaler {
	return &u2fRegistrationMarshaler{}
}

type u2fRegistrationMarshaler struct{}

func (_ *u2fRegistrationMarshaler) Marshal(registration U2FRegistration, opts ...MarshalOption) ([]byte, error) {
	cfg, err := collectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	switch r := registration.(type) {
	case *U2FRegistrationV1:
		if !cfg.PreserveResourceID {
			// avoid modifying original object
			cp := *r
			cp.SetResourceID(0)
			r = &cp
		}
		bytes, err := utils.FastMarshal(r)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return bytes, nil
	default:
		return nil, trace.NotImplemented("unknown u2f registration type %T", registration)
	}
}

func (_ *u2fRegistrationMarshaler) Unmarshal(bytes []byte, opts ...MarshalOption) (U2FRegistration, error) {
	var registration U2FRegistrationV1

	if len(bytes) == 0 {
		return nil, trace.BadParameter("missing resource data")
	}

	cfg, err := collectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if cfg.SkipValidation {
		if err := utils.FastUnmarshal(bytes, &registration); err != nil {
			return nil, trace.BadParameter(err.Error())
		}
	} else {
		err := utils.UnmarshalWithSchema(GetU2FRegistrationSchema(), &registration, bytes)
		if err != nil {
			return nil, trace.BadParameter(err.Error())
		}
	}
	if cfg.ID != 0 {
		registration.SetResourceID(cfg.ID)
	}
	if !cfg.Expires.IsZero() {
		registration.SetExpiry(cfg.Expires)
	}
	return &registration, nil
}

// GetU2FRegistrationSchema returns JSON schema for u2f registration resource.
func GetU2FRegistrationSchema() string {
	return fmt.Sprintf(V2SchemaTemplate, MetadataSchema, U2FRegistrationSpecSchemaV1, DefaultDefinitions)
}

// U2FRegistrationSpecSchemaV1 is a JSON schema for universal second factor registration spec.
const U2FRegistrationSpecSchemaV1 = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["raw","key_handle","pubkey"],
  "properties": {
    "raw": {"type": "string"},
	"key_handle": {"type": "string"},
	"pubkey": {"type": "string"}
  }
}`

// FIXME
func (r *U2FRegistrationCounterV1) String() string {
	return fmt.Sprintf("U2FRegistrationCounter(user=%q,count=%v)", r.Metadata.Name, r.Spec.Counter)
}
