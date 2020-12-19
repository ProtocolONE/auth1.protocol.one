package entity

import (
	"errors"
	"fmt"
)

// IdentityProviders set of providers related to one space
// ensures that always exist default provider (local password)
// ensures that each provider has unique name
type IdentityProviders []IdentityProvider

// NewIdentityProviders returns new id providers set (with initialized default one)
func NewIdentityProviders() IdentityProviders {
	return IdentityProviders{{
		Type:        IDProviderTypePassword,
		Name:        IDProviderNameDefault,
		DisplayName: "Initial connection",
	}}
}

func (providers IdentityProviders) DefaultIDProvider() IdentityProvider {
	for i := range providers {
		if providers[i].IsDefault() {
			return providers[i]
		}
	}
	panic("missing default identity provider")
}

func (providers IdentityProviders) SocialProviders() []IdentityProvider {
	var result = make([]IdentityProvider, 0, 16)
	for i := range providers {
		if providers[i].IsSocial() {
			result = append(result, providers[i])
		}
	}
	return result
}

func (providers IdentityProviders) IDProvider(id IdentityProviderID) (IdentityProvider, bool) {
	for i := range providers {
		if providers[i].ID == id {
			return providers[i], true
		}
	}
	return IdentityProvider{}, false
}

func (providers IdentityProviders) IDProviderName(name string) (IdentityProvider, bool) {
	for i := range providers {
		if providers[i].Name == name {
			return providers[i], true
		}
	}
	return IdentityProvider{}, false
}

func (providers *IdentityProviders) AddIDProvider(p IdentityProvider) error {
	p.ID = ""
	for i := range *providers {
		if (*providers)[i].Name == p.Name {
			return fmt.Errorf("id provider with name '%s' already exist", p.Name)
		}
	}

	*providers = append(*providers, p)
	return nil
}

func (providers IdentityProviders) UpdateIDProvider(p IdentityProvider) error {
	i, ok := providers.findIndex(p.ID)
	if !ok {
		return fmt.Errorf("id provider with id '%s' not found", p.ID)
	}

	if providers[i].Type != p.Type {
		return errors.New("can't update provider type")
	}

	if providers[i].Name != p.Name {
		if providers[i].IsDefault() {
			return errors.New("can't update default provider name")
		}

		for i := range providers {
			if providers[i].Name == p.Name {
				return fmt.Errorf("id provider with name '%s' already exist", p.Name)
			}
		}
	}

	providers[i] = p
	return nil
}

func (providers *IdentityProviders) RemoveIDProvider(id IdentityProviderID) error {
	p := *providers
	i, ok := p.findIndex(id)
	if !ok {
		return fmt.Errorf("id provider with id '%s' not found", id)
	}

	if p[i].IsDefault() {
		return fmt.Errorf("can't remove default provider")
	}

	p[i] = p[len(p)-1]
	*providers = p[:len(p)-1]
	return nil
}

func (providers IdentityProviders) findIndex(id IdentityProviderID) (int, bool) {
	for i := range providers {
		if providers[i].ID == id {
			return i, true
		}
	}
	return 0, false
}
