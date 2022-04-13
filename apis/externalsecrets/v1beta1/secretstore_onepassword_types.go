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

package v1beta1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

type OnePasswordProvider struct {
	// Host is the Endpoint URL that is specific to the Secrets Manager service instance
	Host *string `json:"host,omitempty"`
	// Vault is the internal 1pass vault from where to get secrets
	Vault *string `json:"vault,omitempty"`
	// Auth configures how the operator authenticates with OnePassword.
	Auth *OnePasswordAuth `json:"authSecretRef"`
}

type OnePasswordAuth struct {
	SecretRef OnePasswordAuthSecretRef `json:"secretRef"`
}

type OnePasswordAuthSecretRef struct {
	Token esmeta.SecretKeySelector `json:"tokenSecretRef,omitempty"`
}
