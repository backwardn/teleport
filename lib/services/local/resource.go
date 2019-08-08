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
	items, err := ItemizeResources(resources...)
	if err != nil {
		return trace.Wrap(err)
	}
	// ensure all items do not exist before continuing.
	for _, item := range items {
		_, err = b.Get(ctx, item.Key)
		if !trace.IsNotFound(err) {
			if err != nil {
				return trace.Wrap(err)
			}
			return trace.AlreadyExists("resource %q already exists", string(item.Key))
		}
	}
	// create all items.
	for _, item := range items {
		_, err := b.Create(ctx, item)
		if err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

func ItemizeResources(resources ...services.Resource) ([]backend.Item, error) {
	var allItems []backend.Item
	for _, rsc := range resources {
		items, err := ItemizeResource(rsc)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		allItems = append(allItems, items...)
	}
	return allItems, nil
}

// ItemizeResource attempts to construct one or more instances of `backend.Item` from
// a given resource.  If `rsc` is not one of the supported resource types,
// a `trace.NotImplementedError` is returned.
func ItemizeResource(resource services.Resource) ([]backend.Item, error) {
	var item *backend.Item
	var extItems []backend.Item
	var err error
	switch r := resource.(type) {
	case services.User:
		item, err = itemizeUser(r)
		if auth := r.GetLocalAuth(); err == nil && auth != nil {
			extItems, err = itemizeLocalAuthSecrets(r.GetName(), *auth)
		}
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
	case services.U2FRegistrationCounter:
		item, err = itemizeU2FRegistrationCounter(r)
	case services.PasswordHash:
		item, err = itemizePasswordHash(r)
	default:
		return nil, trace.NotImplemented("cannot itemize resource of type %T", resource)
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}
	items := make([]backend.Item, 0, len(extItems)+1)
	items = append(items, *item)
	items = append(items, extItems...)
	return items, nil
}

// DeitemizeResources converts one or more items into one or more resources.
// NOTE: This is not necessarily a 1-to-1 conversion, and order is not preserved.
func DeitemizeResources(items ...backend.Item) ([]services.Resource, error) {
	var resources []services.Resource
	// User resources may be split across multiple items, so we must extract them first.
	users, rem, err := collectUserItems(items)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	for uname, uitems := range users {
		user, err := deitemizeUserItems(uname, uitems)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		resources = append(resources, user)
	}
	for _, item := range rem {
		rsc, err := DeitemizeResource(item)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		resources = append(resources, rsc)
	}
	return resources, nil
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

// deitemizeUserItems is an extended variant of deitemizeUser which can be used
// with the `userItems` collector to include additional backend.Item values
// such as password hash or u2f registration.
func deitemizeUserItems(name string, items userItems) (services.User, error) {
	if items.params == nil {
		return nil, trace.BadParameter("cannot deitemize user %q without primary item %q", name, paramsPrefix)
	}
	user, err := deitemizeUser(*items.params)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if items.Len() < 2 {
		return user, nil
	}
	auth, err := deitemizeLocalAuthSecrets(items)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	user.SetLocalAuth(auth)
	return user, nil
}

func deitemizeLocalAuthSecrets(items userItems) (*services.LocalAuthSecrets, error) {
	var auth services.LocalAuthSecrets
	if items.pwd != nil {
		auth.PasswordHash = items.pwd.Value
	}
	if items.totp != nil {
		auth.TOTPKey = string(items.totp.Value)
	}
	if items.u2fRegistration != nil {
		var raw u2fRegistration
		if err := json.Unmarshal(items.u2fRegistration.Value, &raw); err != nil {
			return nil, trace.Wrap(err)
		}
		auth.U2FRegistration = &services.U2FRegistrationData{
			Raw:       raw.Raw,
			KeyHandle: raw.KeyHandle,
			PubKey:    raw.MarshalledPubKey,
		}
	}
	if items.u2fCounter != nil {
		var raw u2fRegistrationCounter
		if err := json.Unmarshal(items.u2fCounter.Value, &raw); err != nil {
			return nil, trace.Wrap(err)
		}
		auth.U2FCounter = raw.Counter
	}
	if err := auth.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &auth, nil
}

func itemizeLocalAuthSecrets(user string, auth services.LocalAuthSecrets) ([]backend.Item, error) {
	var items []backend.Item
	if err := auth.Check(); err != nil {
		return nil, trace.Wrap(err)
	}
	if len(auth.PasswordHash) > 0 {
		item := backend.Item{
			Key:   backend.Key(webPrefix, usersPrefix, user, pwdPrefix),
			Value: auth.PasswordHash,
		}
		items = append(items, item)
	}
	if len(auth.TOTPKey) > 0 {
		item := backend.Item{
			Key:   backend.Key(webPrefix, usersPrefix, user, totpPrefix),
			Value: []byte(auth.TOTPKey),
		}
		items = append(items, item)
	}
	if auth.U2FRegistration != nil {
		value, err := json.Marshal(u2fRegistration{
			Raw:              auth.U2FRegistration.Raw,
			KeyHandle:        auth.U2FRegistration.KeyHandle,
			MarshalledPubKey: auth.U2FRegistration.PubKey,
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		item := backend.Item{
			Key:   backend.Key(webPrefix, usersPrefix, user, u2fRegistrationPrefix),
			Value: value,
		}
		items = append(items, item)
	}
	if auth.U2FCounter > 0 {
		value, err := json.Marshal(u2fRegistrationCounter{
			Counter: auth.U2FCounter,
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		item := backend.Item{
			Key:   backend.Key(webPrefix, usersPrefix, user, u2fRegistrationCounterPrefix),
			Value: value,
		}
		items = append(items, item)
	}
	return items, nil
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

// itemizeU2FRegistrationCounter attempts to encode the supplied registration counter as an
// instance of `backend.Item` suitable for storage.
func itemizeU2FRegistrationCounter(ctr services.U2FRegistrationCounter) (*backend.Item, error) {
	if err := ctr.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	value, err := json.Marshal(u2fRegistrationCounter{
		Counter: ctr.GetCounterValue(),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	item := &backend.Item{
		Key:     backend.Key(webPrefix, usersPrefix, ctr.GetUser(), u2fRegistrationCounterPrefix),
		Value:   value,
		Expires: ctr.Expiry(),
		ID:      ctr.GetResourceID(),
	}
	return item, nil
}

// deitemizeU2FRegistrationCounter attempts to decode the supplied `backend.Item` as
// a registration counter resource.
func deitemizeU2FRegistrationCounter(item backend.Item) (services.U2FRegistrationCounter, error) {
	name, _, err := splitUsernameAndSuffix(string(item.Key))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var raw u2fRegistrationCounter
	if err := json.Unmarshal(item.Value, &raw); err != nil {
		return nil, trace.Wrap(err)
	}
	ctr := services.NewU2FRegistrationCounter(name, raw.Counter)
	ctr.SetExpiry(item.Expires)
	ctr.SetResourceID(item.ID)
	if err := ctr.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return ctr, nil
}

// itemizePasswordHash attempts to encode the supplied password hash as an
// instance of `backend.Item` suitable for storage.
func itemizePasswordHash(hash services.PasswordHash) (*backend.Item, error) {
	if err := hash.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	item := &backend.Item{
		Key:     backend.Key(webPrefix, usersPrefix, hash.GetUser(), pwdPrefix),
		Value:   hash.GetPasswordHash(),
		Expires: hash.Expiry(),
		ID:      hash.GetResourceID(),
	}
	return item, nil
}

// deitemizePasswordHash attempts to decode the supplied `backend.Item` as
// a password hash resource.
func deitemizePasswordHash(item backend.Item) (services.PasswordHash, error) {
	name, _, err := splitUsernameAndSuffix(string(item.Key))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	hash := services.NewPasswordHash(name, item.Value)
	hash.SetExpiry(item.Expires)
	hash.SetResourceID(item.ID)
	if err := hash.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return hash, nil
}

// TODO: convert username/suffix ops to work on bytes by default; string/byte conversion
// has order N cost.

// fullUsersPrefix is the entire string preceeding the name of a user in a key
var fullUsersPrefix string = string(backend.Key(webPrefix, usersPrefix)) + "/"

// splitUsernameAndSuffix is a helper for extracting usernames and suffixes from
// backend key values.
func splitUsernameAndSuffix(key string) (name string, suffix string, err error) {
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

// trimToSuffix trims a key-like value upto and including the last `/` character.
// If no `/` exists, the full value is returned.  If `/` is the last character, an
// empty string is returned.
func trimToSuffix(keyLike string) (suffix string) {
	idx := strings.LastIndex(keyLike, "/")
	if idx < 0 {
		return keyLike
	}
	return keyLike[idx+1:]
}

// collectUserItems handles the case where multiple items pertain to the same user resource.
// User associated items are sorted by username and suffix.  Items which do not both start with
// the expected prefix *and* end with one of the expected suffixes are passed back in `rem`.
func collectUserItems(items []backend.Item) (users map[string]userItems, rem []backend.Item, err error) {
	users = make(map[string]userItems)
	for _, item := range items {
		key := string(item.Key)
		if !strings.HasPrefix(key, fullUsersPrefix) {
			rem = append(rem, item)
			continue
		}
		name, suffix, err := splitUsernameAndSuffix(key)
		if err != nil {
			return nil, nil, err
		}
		collector := users[name]
		if !collector.Set(suffix, &item) {
			// suffix not recognized, output this item with the rest of the
			// unhandled items.
			rem = append(rem, item)
			continue
		}
		users[name] = collector
	}
	return users, rem, nil
}

// userItems is a collector for item types related to a single user resource.
type userItems struct {
	params          *backend.Item
	pwd             *backend.Item
	totp            *backend.Item
	u2fRegistration *backend.Item
	u2fCounter      *backend.Item
}

// Set attempts to set a field by suffix (use nil to clear a field).
func (u *userItems) Set(suffix string, item *backend.Item) (ok bool) {
	switch suffix {
	case paramsPrefix:
		u.params = item
	case pwdPrefix:
		u.pwd = item
	case totpPrefix:
		u.totp = item
	case u2fRegistrationPrefix:
		u.u2fRegistration = item
	case u2fRegistrationCounterPrefix:
		u.u2fCounter = item
	default:
		return false
	}
	return true
}

func (u *userItems) slots() [5]*backend.Item {
	return [5]*backend.Item{
		u.params,
		u.pwd,
		u.totp,
		u.u2fRegistration,
		u.u2fCounter,
	}
}

func (u *userItems) Len() int {
	var l int
	for _, s := range u.slots() {
		if s != nil {
			l++
		}
	}
	return l
}
