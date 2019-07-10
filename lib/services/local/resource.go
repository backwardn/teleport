/*
Copyright 2019 Gravitational, Inc.

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

package local

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
)

// CreateResources attempts to dynamically create the supplied resources.
// This function returns `trace.AlreadyExistsError` if one or more resources
// would be overwritten, and `trace.NotImplementedError` if any resources
// are of an unsupported type (see `ItemizeResource(...)`).
//
// NOTE: This function is non-atomic and performs no internal synchronization;
// backend must be locked by caller when operating in parallel environment.
func CreateResources(ctx context.Context, b backend.Backend, resources ...services.Resource) error {
	var items []*backend.Item
	// itemize all resources & ensure that they do not exist.
	for _, r := range resources {
		item, err := ItemizeResource(r)
		if err != nil {
			return trace.Wrap(err)
		}
		_, err = b.Get(ctx, item.Key)
		if !trace.IsNotFound(err) {
			if err != nil {
				return trace.Wrap(err)
			}
			return trace.AlreadyExists("resource %q already exists", string(item.Key))
		}
		items = append(items, item)
	}
	// create all items.
	for _, item := range items {
		_, err := b.Create(context.TODO(), *item)
		if err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// ItemizeResource attempts to construct an instance of `backend.Item` from
// a given resource.  If `rsc` is not one of the supported resource types,
// a `trace.NotImplementedError` is returned.
func ItemizeResource(resource services.Resource) (*backend.Item, error) {
	var item *backend.Item
	var err error
	switch r := resource.(type) {
	case services.User:
		item, err = itemizeUser(r)
	case services.CertAuthority:
		item, err = itemizeCertAuthority(r)
	case services.TrustedCluster:
		item, err = itemizeTrustedCluster(r)
	case services.GithubConnector:
		item, err = itemizeGithubConnector(r)
	case services.Role:
		item, err = itemizeRole(r)
	case services.OIDCConnector:
		item, err = itemizeOIDCConnector(r)
	case services.SAMLConnector:
		item, err = itemizeSAMLConnector(r)
	case services.OTPVerifier:
		item, err = itemizeOTPVerifier(r)
	case services.U2FRegistration:
		item, err = itemizeU2FRegistration(r)
	default:
		return nil, trace.NotImplemented("cannot itemize resource of type %T", resource)
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return item, nil
}

// DeitemizeResource attempts to decode the supplied `backend.Item` as one
// of the supported resource types.  If the resource's `kind` does not match
// one of the supported resource types, `trace.NotImplementedError` is returned.
func DeitemizeResource(item backend.Item) (services.Resource, error) {
	var u services.UnknownResource
	if err := u.UnmarshalJSON(item.Value); err != nil || u.GetKind() == "" {
		// Special Case: certain values are not currently stored in their resource
		// form, and therefore must be identified by their suffix instead. If we
		// failed to unmarshal the item as JSON, or if the 'kind' field was missing,
		// then we might be be dealing with one of the non-conformant types.
		key := string(item.Key)
		switch {
		case strings.HasSuffix(key, "otp"): // match all `*otp` types
			verifier, err := deitemizeOTPVerifier(item)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			return verifier, nil
		case strings.HasSuffix(key, u2fRegistrationPrefix):
			reg, err := deitemizeU2FRegistration(item)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			return reg, nil
		default:
			// we got here for one of two reasons; invalid json or missing `kind` field.
			if err != nil {
				return nil, trace.Wrap(err)
			}
			return nil, trace.BadParameter("resource missing expected field 'kind'")
		}
	}
	var rsc services.Resource
	var err error
	switch kind := u.GetKind(); kind {
	case services.KindUser:
		rsc, err = deitemizeUser(item)
	case services.KindCertAuthority:
		rsc, err = deitemizeCertAuthority(item)
	case services.KindTrustedCluster:
		rsc, err = deitemizeTrustedCluster(item)
	case services.KindGithubConnector:
		rsc, err = deitemizeGithubConnector(item)
	case services.KindRole:
		rsc, err = deitemizeRole(item)
	case services.KindOIDCConnector:
		rsc, err = deitemizeOIDCConnector(item)
	case services.KindSAMLConnector:
		rsc, err = deitemizeSAMLConnector(item)
	default:
		return nil, trace.NotImplemented("cannot dynamically decode resource of kind %q", kind)
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return rsc, nil
}

// itemizeUser attempts to encode the supplied user as an
// instance of `backend.Item` suitable for storage.
func itemizeUser(user services.User) (*backend.Item, error) {
	if err := user.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	value, err := services.GetUserMarshaler().MarshalUser(user)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	item := &backend.Item{
		Key:     backend.Key(webPrefix, usersPrefix, user.GetName(), paramsPrefix),
		Value:   value,
		Expires: user.Expiry(),
		ID:      user.GetResourceID(),
	}
	return item, nil
}

// deitemizeUser attempts to decode the supplied `backend.Item` as
// a user resource.
func deitemizeUser(item backend.Item) (services.User, error) {
	user, err := services.GetUserMarshaler().UnmarshalUser(
		item.Value,
		services.WithResourceID(item.ID),
		services.WithExpires(item.Expires),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := user.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	return user, nil
}

// itemizeCertAuthority attempts to encode the supplied certificate authority
// as an instance of `backend.Item` suitable for storage.
func itemizeCertAuthority(ca services.CertAuthority) (*backend.Item, error) {
	if err := ca.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	value, err := services.GetCertAuthorityMarshaler().MarshalCertAuthority(ca)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	item := &backend.Item{
		Key:     backend.Key(authoritiesPrefix, string(ca.GetType()), ca.GetName()),
		Value:   value,
		Expires: ca.Expiry(),
		ID:      ca.GetResourceID(),
	}
	return item, nil
}

// deitemizeCertAuthority attempts to decode the supplied `backend.Item` as
// a certificate authority resource (NOTE: does not filter secrets).
func deitemizeCertAuthority(item backend.Item) (services.CertAuthority, error) {
	ca, err := services.GetCertAuthorityMarshaler().UnmarshalCertAuthority(
		item.Value,
		services.WithResourceID(item.ID),
		services.WithExpires(item.Expires),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := ca.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	return ca, nil
}

// itemizeTrustedCluster attempts to encode the supplied trusted cluster
// as an instance of `backend.Item` suitable for storage.
func itemizeTrustedCluster(tc services.TrustedCluster) (*backend.Item, error) {
	if err := tc.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	value, err := services.GetTrustedClusterMarshaler().Marshal(tc)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	item := &backend.Item{
		Key:     backend.Key(trustedClustersPrefix, tc.GetName()),
		Value:   value,
		Expires: tc.Expiry(),
		ID:      tc.GetResourceID(),
	}
	return item, nil
}

// deitemizeTrustedCluster attempts to decode the supplied `backend.Item` as
// a trusted cluster resource.
func deitemizeTrustedCluster(item backend.Item) (services.TrustedCluster, error) {
	tc, err := services.GetTrustedClusterMarshaler().Unmarshal(
		item.Value,
		services.WithResourceID(item.ID),
		services.WithExpires(item.Expires),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return tc, nil
}

// itemizeGithubConnector attempts to encode the supplied github connector
// as an instance of `backend.Item` suitable for storage.
func itemizeGithubConnector(gc services.GithubConnector) (*backend.Item, error) {
	if err := gc.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	value, err := services.GetGithubConnectorMarshaler().Marshal(gc)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	item := &backend.Item{
		Key:     backend.Key(webPrefix, connectorsPrefix, githubPrefix, connectorsPrefix, gc.GetName()),
		Value:   value,
		Expires: gc.Expiry(),
		ID:      gc.GetResourceID(),
	}
	return item, nil
}

// deitemizeGithubConnector attempts to decode the supplied `backend.Item` as
// a github connector resource.
func deitemizeGithubConnector(item backend.Item) (services.GithubConnector, error) {
	// XXX: The `GithubConnectorMarshaler` interface is an outlier in that it
	// does not support marshal options (e.g. `WithResourceID(..)`).  Support should
	// be added unless this is an intentional omission.
	gc, err := services.GetGithubConnectorMarshaler().Unmarshal(item.Value)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return gc, nil
}

// itemizeRole attempts to encode the supplied role as an
// instance of `backend.Item` suitable for storage.
func itemizeRole(role services.Role) (*backend.Item, error) {
	value, err := services.GetRoleMarshaler().MarshalRole(role)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	item := &backend.Item{
		Key:     backend.Key(rolesPrefix, role.GetName(), paramsPrefix),
		Value:   value,
		Expires: role.Expiry(),
		ID:      role.GetResourceID(),
	}
	return item, nil
}

// deitemizeRole attempts to decode the supplied `backend.Item` as
// a role resource.
func deitemizeRole(item backend.Item) (services.Role, error) {
	role, err := services.GetRoleMarshaler().UnmarshalRole(
		item.Value,
		services.WithResourceID(item.ID),
		services.WithExpires(item.Expires),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return role, nil
}

// itemizeOIDCConnector attempts to encode the supplied connector as an
// instance of `backend.Item` suitable for storage.
func itemizeOIDCConnector(connector services.OIDCConnector) (*backend.Item, error) {
	if err := connector.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	value, err := services.GetOIDCConnectorMarshaler().MarshalOIDCConnector(connector)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	item := &backend.Item{
		Key:     backend.Key(webPrefix, connectorsPrefix, oidcPrefix, connectorsPrefix, connector.GetName()),
		Value:   value,
		Expires: connector.Expiry(),
		ID:      connector.GetResourceID(),
	}
	return item, nil
}

// deitemizeOIDCConnector attempts to decode the supplied `backend.Item` as
// an oidc connector resource.
func deitemizeOIDCConnector(item backend.Item) (services.OIDCConnector, error) {
	connector, err := services.GetOIDCConnectorMarshaler().UnmarshalOIDCConnector(
		item.Value,
		services.WithResourceID(item.ID),
		services.WithExpires(item.Expires),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return connector, nil
}

// itemizeSAMLConnector attempts to encode the supplied connector as an
// instance of `backend.Item` suitable for storage.
func itemizeSAMLConnector(connector services.SAMLConnector) (*backend.Item, error) {
	if err := connector.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	value, err := services.GetSAMLConnectorMarshaler().MarshalSAMLConnector(connector)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	item := &backend.Item{
		Key:     backend.Key(webPrefix, connectorsPrefix, samlPrefix, connectorsPrefix, connector.GetName()),
		Value:   value,
		Expires: connector.Expiry(),
		ID:      connector.GetResourceID(),
	}
	return item, nil
}

// deitemizeSAMLConnector attempts to decode the supplied `backend.Item` as
// a saml connector resource.
func deitemizeSAMLConnector(item backend.Item) (services.SAMLConnector, error) {
	connector, err := services.GetSAMLConnectorMarshaler().UnmarshalSAMLConnector(
		item.Value,
		services.WithResourceID(item.ID),
		services.WithExpires(item.Expires),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return connector, nil
}

// itemizeOTPVerifier attempts to encode the supplied verifier as an
// instance of `backend.Item` suitable for storage.
func itemizeOTPVerifier(verifier services.OTPVerifier) (*backend.Item, error) {
	if err := verifier.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	value := []byte(verifier.GetOTPKey())
	item := &backend.Item{
		Key:     backend.Key(webPrefix, usersPrefix, verifier.GetUser(), verifier.GetSubKind()),
		Value:   value,
		Expires: verifier.Expiry(),
		ID:      verifier.GetResourceID(),
	}
	return item, nil
}

// deitemizeOTPVerifier attempts to decode the supplied `backend.Item` as
// an otp verifier resource.
func deitemizeOTPVerifier(item backend.Item) (services.OTPVerifier, error) {
	name, subkind, err := splitUsernameAndSuffix(string(item.Key))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	verifier := services.NewOTPVerifier(name, string(item.Value))
	verifier.SetSubKind(subkind)
	verifier.SetExpiry(item.Expires)
	verifier.SetResourceID(item.ID)
	if err := verifier.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return verifier, nil
}

// itemizeU2FRegistration attempts to encode the supplied registration as an
// instance of `backend.Item` suitable for storage.
func itemizeU2FRegistration(reg services.U2FRegistration) (*backend.Item, error) {
	if err := reg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	value, err := json.Marshal(u2fRegistration{
		Raw:              reg.GetRawRegistration(),
		KeyHandle:        reg.GetKeyHandle(),
		MarshalledPubKey: reg.GetPubKeyDER(),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	item := &backend.Item{
		Key:     backend.Key(webPrefix, usersPrefix, reg.GetUser(), u2fRegistrationPrefix),
		Value:   value,
		Expires: reg.Expiry(),
		ID:      reg.GetResourceID(),
	}
	return item, nil
}

// deitemizeU2FRegistration attempts to decode the supplied `backend.Item` as
// a u2f registration resource.
func deitemizeU2FRegistration(item backend.Item) (services.U2FRegistration, error) {
	name, _, err := splitUsernameAndSuffix(string(item.Key))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var raw u2fRegistration
	if err := json.Unmarshal(item.Value, &raw); err != nil {
		return nil, trace.Wrap(err)
	}
	reg := services.NewU2FRegistration(name, raw.Raw, raw.KeyHandle, raw.MarshalledPubKey)
	reg.SetExpiry(item.Expires)
	reg.SetResourceID(item.ID)
	if err := reg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return reg, nil
}

// fullUsersPrefix is the entire string preceeding the name of a user in a key
var fullUsersPrefix string = string(backend.Key(webPrefix, usersPrefix)) + "/"

// splitUsernameAndSuffix is a helper for extracting usernames and suffixes from
// backend key values.
func splitUsernameAndSuffix(key string) (string, string, error) {
	if !strings.HasPrefix(key, fullUsersPrefix) {
		return "", "", trace.BadParameter("expected format '%s/<name>/<suffix>', got '%s'", fullUsersPrefix, key)
	}
	key = strings.TrimPrefix(key, fullUsersPrefix)
	idx := strings.LastIndex(key, "/")
	if idx < 1 || idx >= len(key) {
		return "", "", trace.BadParameter("expected format <name>/<suffix>, got %q", key)
	}
	return key[:idx], key[idx+1:], nil
}
