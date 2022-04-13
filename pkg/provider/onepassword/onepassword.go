/*
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

package onepassword

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/types"

	corev1 "k8s.io/api/core/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/1Password/connect-sdk-go/connect"
	"github.com/1Password/connect-sdk-go/onepassword"
	"github.com/external-secrets/external-secrets/pkg/utils"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
)

const (
	errOnePasswordClient                     = "cannot setup new onepassword client: %w"
	errOnePasswordCredSecretName             = "invalid onepassword SecretStore resource: missing onepassword APIKey"
	errUninitalizedOnePasswordProvider       = "provider onepassword is not initialized"
	errInvalidClusterStoreMissingSKNamespace = "invalid ClusterStore, missing namespace"
	errFetchSAKSecret                        = "could not fetch SecretAccessKey secret: %w"
	errMissingSAK                            = "missing SecretAccessKey"
	errMissingVault                          = "missing Vault"
	errJSONSecretUnmarshal                   = "unable to unmarshal secret: %w"
)

// https://github.com/external-secrets/external-secrets/issues/644
var _ esv1beta1.SecretsClient = &providerOnePassword{}
var _ esv1beta1.Provider = &providerOnePassword{}

type OnePasswordClient interface {
	GetItemByTitle(title string, vaultUUID string) (*onepassword.Item, error)
}

type providerOnePassword struct {
	OnePasswordClient OnePasswordClient
	vault             string
}

type oneClient struct {
	kube        kclient.Client
	store       *esv1beta1.OnePasswordProvider
	credentials []byte
	vault       string
	namespace   string
	storeKind   string
}

func (c *oneClient) setAuth(ctx context.Context) error {
	credentialsSecret := &corev1.Secret{}
	credentialsSecretName := c.store.Auth.SecretRef.Token.Name
	if credentialsSecretName == "" {
		return fmt.Errorf(errOnePasswordCredSecretName)
	}
	objectKey := types.NamespacedName{
		Name:      credentialsSecretName,
		Namespace: c.namespace,
	}

	// only ClusterStore is allowed to set namespace (and then it's required)
	if c.storeKind == esv1beta1.ClusterSecretStoreKind {
		if c.store.Auth.SecretRef.Token.Namespace == nil {
			return fmt.Errorf(errInvalidClusterStoreMissingSKNamespace)
		}
		objectKey.Namespace = *c.store.Auth.SecretRef.Token.Namespace
	}

	err := c.kube.Get(ctx, objectKey, credentialsSecret)
	if err != nil {
		return fmt.Errorf(errFetchSAKSecret, err)
	}

	c.credentials = credentialsSecret.Data[c.store.Auth.SecretRef.Token.Key]

	if (c.credentials == nil) || (len(c.credentials) == 0) {
		return fmt.Errorf(errMissingSAK)
	}
	c.vault = *c.store.Vault
	if c.vault == "" {
		return fmt.Errorf(errMissingVault)
	}
	return nil
}

func (onepassword *providerOnePassword) NewClient(ctx context.Context, store esv1beta1.GenericStore, kube kclient.Client, namespace string) (esv1beta1.SecretsClient, error) {
	storeSpec := store.GetSpec()
	onePasswordSpec := storeSpec.Provider.OnePassword
	oneStore := &oneClient{
		kube:      kube,
		store:     onePasswordSpec,
		namespace: namespace,
		storeKind: store.GetObjectKind().GroupVersionKind().Kind,
	}
	if err := oneStore.setAuth(ctx); err != nil {
		return nil, err
	}
	onepassword.vault = *oneStore.store.Vault
	onePasswordClient := connect.NewClient(*oneStore.store.Host, string(oneStore.credentials))
	onepassword.OnePasswordClient = onePasswordClient

	return onepassword, nil
}

func (onepassword *providerOnePassword) ValidateStore(store esv1beta1.GenericStore) error {
	return nil
}

func (onepassword *providerOnePassword) GetSecret(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) ([]byte, error) {
	if utils.IsNil(onepassword.OnePasswordClient) {
		return nil, fmt.Errorf(errUninitalizedOnePasswordProvider)
	}

	response, err := onepassword.OnePasswordClient.GetItemByTitle(ref.Key, onepassword.vault)
	if err != nil {
		return nil, err
	}

	if ref.Property == "" {
		if response.Fields != nil && len(response.Fields) > 0 {
			return []byte(response.GetValue("password")), nil
		}
		return nil, fmt.Errorf("invalid secret received. no secret string for key: %s", ref.Key)
	}

	idx := strings.Index(ref.Property, ".")
	refProperty := ref.Property
	if idx > 0 {
		refProperty = strings.ReplaceAll(refProperty, ".", "\\.")
		val := response.GetValue(refProperty)
		if val != "" {
			return []byte(val), nil
		}
	}

	val := response.GetValue(refProperty)
	if val == "" {
		return nil, fmt.Errorf("key %s is not existent secret %s", ref.Property, ref.Key)
	}
	return []byte(val), nil
}

func (onepassword *providerOnePassword) Validate() error {
	return nil
}

func (onepassword *providerOnePassword) GetSecretMap(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	return make(map[string][]byte), nil
}

func (onepassword *providerOnePassword) GetAllSecrets(ctx context.Context, ref esv1beta1.ExternalSecretFind) (map[string][]byte, error) {
	return make(map[string][]byte), nil
}

func (onepassword *providerOnePassword) Close(ctx context.Context) error {
	return nil
}

func init() {
	esv1beta1.Register(&providerOnePassword{}, &esv1beta1.SecretStoreProvider{
		OnePassword: &esv1beta1.OnePasswordProvider{},
	})
}
