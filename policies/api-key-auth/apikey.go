/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package apikey

import (
	"log/slog"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

const (
	// Metadata keys for context storage
	MetadataKeyAuthSuccess = "auth.success"
	MetadataKeyAuthMethod  = "auth.method"
)

// APIKeyPolicy implements API Key Authentication
type APIKeyPolicy struct {
}

var ins = &APIKeyPolicy{}

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}

// Mode returns the processing mode for this policy
func (p *APIKeyPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess, // Process request headers for auth
		RequestBodyMode:    policy.BodyModeSkip,      // Don't need request body
		ResponseHeaderMode: policy.HeaderModeSkip,    // Don't process response headers
		ResponseBodyMode:   policy.BodyModeSkip,      // Don't need response body
	}
}

// OnRequest performs API Key Authentication
func (p *APIKeyPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	slog.Info("Thushani")
	return nil
}

// OnResponse is not used by this policy (authentication is request-only)
func (p *APIKeyPolicy) OnResponse(_ctx *policy.ResponseContext, _params map[string]interface{}) policy.ResponseAction {
	return nil // No response processing needed
}
