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
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	store "github.com/wso2/api-platform/common/apikey"
	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)


const (
	AuthType = "apikey"
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
	if errResp := p.authenticate(ctx.SharedContext, ctx.Headers, ctx.Path, ctx.Method, params); errResp != nil {
		return *errResp
	}
	return policy.UpstreamRequestModifications{}
}

// handleAuthSuccess handles successful authentication
func (p *APIKeyPolicy) handleAuthSuccess(ctx *policy.RequestContext) policy.RequestAction {
	slog.Debug("API Key Auth Policy: handleAuthSuccess called",
		"apiId", ctx.APIId,
		"apiName", ctx.APIName,
		"apiVersion", ctx.APIVersion,
		"method", ctx.Method,
		"path", ctx.Path,
	)

	ctx.SharedContext.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		Previous:      ctx.SharedContext.AuthContext,
	}

	// Continue to upstream with no modifications
	return policy.UpstreamRequestModifications{}
}

// OnResponse is not used by this policy (authentication is request-only)
func (p *APIKeyPolicy) OnResponse(_ctx *policy.ResponseContext, _params map[string]interface{}) policy.ResponseAction {
	return nil // No response processing needed
}

// handleAuthFailure handles authentication failure
func (p *APIKeyPolicy) handleAuthFailure(ctx *policy.RequestContext, statusCode int, errorFormat, errorMessage,
	reason string) policy.RequestAction {
	slog.Debug("API Key Auth Policy: handleAuthFailure called",
		"statusCode", statusCode,
		"errorFormat", errorFormat,
		"errorMessage", errorMessage,
		"reason", reason,
		"apiId", ctx.APIId,
		"apiName", ctx.APIName,
		"apiVersion", ctx.APIVersion,
		"method", ctx.Method,
		"path", ctx.Path,
	)

	ctx.SharedContext.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		Previous:      ctx.SharedContext.AuthContext,
	}

	return p.buildErrorResponse(statusCode, errorFormat, errorMessage, reason)
}

// authenticate is the shared core logic for both OnRequest and OnRequestHeaders.
// It extracts and validates the API key, sets SharedContext.AuthContext, and returns
// nil on success or an *ImmediateResponse on failure.
func (p *APIKeyPolicy) authenticate(
	shared *policy.SharedContext,
	headers *policy.Headers,
	path, method string,
	params map[string]interface{},
) *policy.ImmediateResponse {
	slog.Debug("API Key Auth Policy: authenticate started",
		"path", path,
		"method", method,
		"apiId", shared.APIId,
		"apiName", shared.APIName,
		"apiVersion", shared.APIVersion,
	)

	keyName, ok := params["key"].(string)
	if !ok || keyName == "" {
		slog.Debug("API Key Auth Policy: Missing or invalid 'key' configuration")
		return p.failAuth(shared, 401, "json", "Valid API key required",
			"missing or invalid 'key' configuration")
	}

	location, ok := params["in"].(string)
	if !ok || location == "" {
		slog.Debug("API Key Auth Policy: Missing or invalid 'in' configuration")
		return p.failAuth(shared, 401, "json", "Valid API key required",
			"missing or invalid 'in' configuration")
	}

	slog.Debug("API Key Auth Policy: Configuration loaded", "keyName", keyName, "location", location)

	var providedKey string
	switch location {
	case "header":
		if vals := headers.Get(http.CanonicalHeaderKey(keyName)); len(vals) > 0 {
			providedKey = vals[0]
			slog.Debug("API Key Auth Policy: Found API key in header",
				"headerName", keyName, "keyLength", len(providedKey))
		}
	case "query":
		providedKey = extractQueryParam(path, keyName)
		if providedKey != "" {
			slog.Debug("API Key Auth Policy: Found API key in query parameter",
				"paramName", keyName, "keyLength", len(providedKey))
		}
	default:
		slog.Debug("API Key Auth Policy: Unsupported location", "location", location)
		return p.failAuth(shared, 401, "json", "Valid API key required",
			"missing or invalid 'in' configuration")
	}

	if providedKey == "" {
		slog.Debug("API Key Auth Policy: No API key found", "location", location, "keyName", keyName)
		return p.failAuth(shared, 401, "json", "Valid API key required", "missing API key")
	}

	apiId := shared.APIId
	apiName := shared.APIName
	apiVersion := shared.APIVersion
	apiOperation := shared.OperationPath
	operationMethod := method

	if apiId == "" || apiName == "" || apiVersion == "" || apiOperation == "" || operationMethod == "" {
		slog.Debug("API Key Auth Policy: Missing API details for validation",
			"apiId", apiId, "apiName", apiName, "apiVersion", apiVersion,
			"apiOperation", apiOperation, "operationMethod", operationMethod)
		return p.failAuth(shared, 401, "json", "Valid API key required",
			"missing API details for validation")
	}

	slog.Debug("API Key Auth Policy: Starting validation",
		"apiId", apiId, "apiName", apiName, "apiVersion", apiVersion,
		"apiOperation", apiOperation, "operationMethod", operationMethod,
		"keyLength", len(providedKey))

	isValid, err := p.validateAPIKey(apiId, apiOperation, operationMethod, providedKey)
	if err != nil {
		slog.Debug("API Key Auth Policy: Validation error", "error", err)
		return p.failAuth(shared, 401, "json", "Valid API key required",
			"error validating API key")
	}
	if !isValid {
		slog.Debug("API Key Auth Policy: Invalid API key")
		return p.failAuth(shared, 401, "json", "Valid API key required", "invalid API key")
	}

	slog.Debug("API Key Auth Policy: Authentication successful")
	shared.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		Previous:      shared.AuthContext,
	}
	return nil
}

// failAuth sets the auth context to unauthenticated and returns an ImmediateResponse.
func (p *APIKeyPolicy) failAuth(shared *policy.SharedContext, statusCode int, errorFormat, errorMessage, reason string) *policy.ImmediateResponse {
	shared.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		Previous:      shared.AuthContext,
	}
	resp := p.buildErrorResponse(statusCode, errorFormat, errorMessage, reason)
	return &resp
}

// buildErrorResponse constructs the ImmediateResponse body and headers for an auth failure.
func (p *APIKeyPolicy) buildErrorResponse(statusCode int, errorFormat, errorMessage, reason string) policy.ImmediateResponse {
	headers := map[string]string{"content-type": "application/json"}

	var body string
	switch errorFormat {
	case "plain":
		body = errorMessage
		headers["content-type"] = "text/plain"
	default: // json
		errResponse := map[string]interface{}{
			"error":   "Unauthorized",
			"message": errorMessage,
		}
		bodyBytes, _ := json.Marshal(errResponse)
		body = string(bodyBytes)
	}

	slog.Debug("API Key Auth Policy: Returning immediate response",
		"statusCode", statusCode,
		"contentType", headers["content-type"],
		"bodyLength", len(body),
		"reason", reason,
	)

	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       []byte(body),
	}
}

// validateAPIKey validates the provided API key against external store/service
func (p *APIKeyPolicy) validateAPIKey(apiId, apiOperation, operationMethod, apiKey string) (bool, error) {
	apiKeyStore := store.GetAPIkeyStoreInstance()
	isValid, err := apiKeyStore.ValidateAPIKey(apiId, apiOperation, operationMethod, apiKey)
	if err != nil {
		return false, fmt.Errorf("failed to validate API key via the policy engine")
	}
	return isValid, nil
}

// ─── v2alpha.RequestHeaderPolicy ─────────────────────────────────────────────

// OnRequestHeaders implements v2alpha.RequestHeaderPolicy.
// It performs API key authentication in the request-header phase, allowing the
// kernel to short-circuit before any body buffering occurs.
func (p *APIKeyPolicy) OnRequestHeaders(ctx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	if errResp := p.authenticate(ctx.SharedContext, ctx.Headers, ctx.Path, ctx.Method, params); errResp != nil {
		return *errResp
	}
	return policy.UpstreamRequestHeaderModifications{}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// extractQueryParam extracts the first value of the given query parameter from the request path
func extractQueryParam(path, param string) string {
	// Parse the URL-encoded path
	decodedPath, err := url.PathUnescape(path)
	if err != nil {
		return ""
	}

	// Split the path into components
	parts := strings.Split(decodedPath, "?")
	if len(parts) != 2 {
		return ""
	}

	// Parse the query string
	queryString := parts[1]
	values, err := url.ParseQuery(queryString)
	if err != nil {
		return ""
	}

	// Get the first value of the specified parameter
	if value, ok := values[param]; ok && len(value) > 0 {
		return value[0]
	}

	return ""
}
