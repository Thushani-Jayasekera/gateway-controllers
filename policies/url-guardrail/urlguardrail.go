/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package urlguardrail

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
	utils "github.com/wso2/api-platform/sdk/utils"
)

const (
	GuardrailErrorCode           = 422
	TextCleanRegex               = "^\"|\"$"
	URLRegex                     = "https?://[^\\s,\"'{}\\[\\]\\\\`*]+"
	DefaultTimeout               = 3000 // milliseconds
	DefaultRequestJSONPath       = "$.messages[-1].content"
	DefaultResponseJSONPath      = "$.choices[0].message.content"
	RequestFlowEnabledByDefault  = false
	ResponseFlowEnabledByDefault = true

	sseDataPrefix = "data: "
	sseDone       = "[DONE]"
)

var (
	textCleanRegexCompiled = regexp.MustCompile(TextCleanRegex)
	urlRegexCompiled       = regexp.MustCompile(URLRegex)
	// partialURLAtEnd matches an http(s):// prefix at the end of a string with
	// no trailing whitespace — indicating a URL that is still being streamed.
	partialURLAtEnd = regexp.MustCompile(`https?://[^\s]*$`)
)

// URLGuardrailPolicy implements URL validation guardrail
type URLGuardrailPolicy struct {
	hasRequestParams  bool
	hasResponseParams bool
	requestParams     URLGuardrailPolicyParams
	responseParams    URLGuardrailPolicyParams
}

type URLGuardrailPolicyParams struct {
	Enabled        bool
	JsonPath       string
	OnlyDNS        bool
	Timeout        int
	ShowAssessment bool
}

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &URLGuardrailPolicy{}

	requestParamsRaw, hasRequest, err := getFlowParams(params, "request")
	if err != nil {
		return nil, err
	}
	if hasRequest {
		requestParams, err := parseParams(requestParamsRaw, DefaultRequestJSONPath, RequestFlowEnabledByDefault)
		if err != nil {
			return nil, fmt.Errorf("invalid request parameters: %w", err)
		}
		p.hasRequestParams = true
		p.requestParams = requestParams
	}

	responseParamsRaw, hasResponse, err := getFlowParams(params, "response")
	if err != nil {
		return nil, err
	}
	if hasResponse {
		responseParams, err := parseParams(responseParamsRaw, DefaultResponseJSONPath, ResponseFlowEnabledByDefault)
		if err != nil {
			return nil, fmt.Errorf("invalid response parameters: %w", err)
		}
		p.hasResponseParams = true
		p.responseParams = responseParams
	}

	// At least one of request or response must be present
	if !p.hasRequestParams && !p.hasResponseParams {
		return nil, fmt.Errorf("at least one of 'request' or 'response' parameters must be provided")
	}

	slog.Debug("URLGuardrail: Policy initialized", "hasRequestParams", p.hasRequestParams, "hasResponseParams", p.hasResponseParams)

	return p, nil
}

func getFlowParams(params map[string]interface{}, flow string) (map[string]interface{}, bool, error) {
	raw, exists := params[flow]
	if !exists {
		return nil, false, nil
	}
	flowParams, ok := raw.(map[string]interface{})
	if !ok {
		return nil, false, fmt.Errorf("'%s' must be an object", flow)
	}
	return flowParams, true, nil
}

// parseParams parses and validates parameters from map to struct
func parseParams(params map[string]interface{}, defaultJSONPath string, defaultEnabled bool) (URLGuardrailPolicyParams, error) {
	result := URLGuardrailPolicyParams{
		JsonPath: defaultJSONPath,
		Enabled:  defaultEnabled,
	}

	// Extract optional enabled parameter
	if enabledRaw, ok := params["enabled"]; ok {
		enabled, ok := enabledRaw.(bool)
		if !ok {
			return result, fmt.Errorf("'enabled' must be a boolean")
		}
		result.Enabled = enabled
	}

	// Extract optional jsonPath parameter
	if jsonPathRaw, ok := params["jsonPath"]; ok {
		if jsonPath, ok := jsonPathRaw.(string); ok {
			result.JsonPath = jsonPath
		} else {
			return result, fmt.Errorf("'jsonPath' must be a string")
		}
	}

	// Extract optional onlyDNS parameter
	if onlyDNSRaw, ok := params["onlyDNS"]; ok {
		if onlyDNS, ok := onlyDNSRaw.(bool); ok {
			result.OnlyDNS = onlyDNS
		} else {
			return result, fmt.Errorf("'onlyDNS' must be a boolean")
		}
	}

	// Extract optional timeout parameter
	if timeoutRaw, ok := params["timeout"]; ok {
		timeout, err := extractInt(timeoutRaw)
		if err != nil {
			return result, fmt.Errorf("'timeout' must be a number: %w", err)
		}
		if timeout < 0 {
			return result, fmt.Errorf("'timeout' cannot be negative")
		}
		result.Timeout = timeout
	} else {
		result.Timeout = DefaultTimeout
	}

	// Extract optional showAssessment parameter
	if showAssessmentRaw, ok := params["showAssessment"]; ok {
		if showAssessment, ok := showAssessmentRaw.(bool); ok {
			result.ShowAssessment = showAssessment
		} else {
			return result, fmt.Errorf("'showAssessment' must be a boolean")
		}
	}

	return result, nil
}

// extractInt safely extracts an integer from various types
func extractInt(value interface{}) (int, error) {
	switch v := value.(type) {
	case int:
		return v, nil
	case int32:
		return int(v), nil
	case int64:
		return int(v), nil
	case float64:
		if v != float64(int(v)) {
			return 0, fmt.Errorf("expected an integer but got %v", v)
		}
		return int(v), nil
	default:
		return 0, fmt.Errorf("cannot convert %T to int", value)
	}
}

// Mode returns the processing mode for this policy
func (p *URLGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// OnRequest delegates to OnRequestBody for v1alpha engine compatibility.
func (p *URLGuardrailPolicy) OnRequest(ctx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	return p.OnRequestBody(ctx)
}

// OnResponse delegates to OnResponseBody for v1alpha engine compatibility.
func (p *URLGuardrailPolicy) OnResponse(ctx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	return p.OnResponseBody(ctx)
}

// OnRequestBody validates URLs found in the request body.
func (p *URLGuardrailPolicy) OnRequestBody(ctx *policy.RequestContext) policy.RequestAction {
	if !p.hasRequestParams || !p.requestParams.Enabled {
		return policy.UpstreamRequestModifications{}
	}

	var content []byte
	if ctx.Body != nil {
		content = ctx.Body.Content
	}
	return p.validatePayload(content, p.requestParams, false).(policy.RequestAction)
}

// OnResponseBody validates URLs found in the response body.
func (p *URLGuardrailPolicy) OnResponseBody(ctx *policy.ResponseContext) policy.ResponseAction {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return policy.UpstreamResponseModifications{}
	}

	var content []byte
	if ctx.ResponseBody != nil {
		content = ctx.ResponseBody.Content
	}
	return p.validatePayload(content, p.responseParams, true).(policy.ResponseAction)
}

// ─── Streaming (SSE) support ──────────────────────────────────────────────────
//
// LLM responses with stream: true arrive as SSE events. Headers (and status)
// are committed before any chunk reaches the policy, so ImmediateResponse
// cannot be used here. If an invalid URL is found the offending chunk is
// replaced with an SSE error event so the downstream client knows the guardrail
// intervened.
//
// Non-SSE streaming bodies are passed through — the buffered OnResponseBody
// already handles them when the kernel falls back to full buffering.

// NeedsMoreResponseData controls how SSE chunks are accumulated before
// OnResponseBodyChunk is called. The goal is to ensure a URL is never
// validated while it is still being streamed token-by-token.
//
// Decision logic (evaluated in order):
//
//  1. Policy disabled → false (pass every chunk through immediately).
//
//  2. data: [DONE] present → false (stream is over; process whatever is
//     accumulated, even if a URL looks incomplete at the very end).
//
//  3. No SSE delta content extracted → false (non-SSE body; the buffered
//     OnResponseBody will handle it when the kernel falls back to full
//     buffering, so there is nothing for the streaming path to do here).
//
//  4. Accumulated delta content ends with `https?://[^\s]*` (a URL that
//     has started but has no whitespace after it yet) → true (keep
//     accumulating; the URL tail is still arriving in subsequent tokens).
//
//  5. Otherwise → false (all URLs in the current window are
//     whitespace-terminated and safe to validate).
func (p *URLGuardrailPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return false
	}

	s := string(accumulated)

	if strings.Contains(s, sseDataPrefix+sseDone) {
		return false
	}

	content := extractSSEDeltaContent(s)
	if content == "" {
		return false
	}

	return partialURLAtEnd.MatchString(content)
}

// OnResponseBodyChunk validates URLs in the accumulated SSE delta content.
// Called once NeedsMoreResponseData returns false (URL complete or stream done).
// On success the original chunk is passed through unchanged (nil Body).
// On failure the chunk is replaced with a structured SSE error event because
// ImmediateResponse is not available after response headers are committed.
func (p *URLGuardrailPolicy) OnResponseBodyChunk(ctx *policy.ResponseStreamContext, chunk *policy.StreamBody, _ map[string]interface{}) policy.ResponseChunkAction {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return policy.ResponseChunkAction{}
	}
	if chunk == nil || len(chunk.Chunk) == 0 {
		return policy.ResponseChunkAction{}
	}

	chunkStr := string(chunk.Chunk)

	// Only validate SSE content; non-SSE chunks are passed through.
	if !strings.Contains(chunkStr, sseDataPrefix) {
		return policy.ResponseChunkAction{}
	}

	content := extractSSEDeltaContent(chunkStr)
	content = textCleanRegexCompiled.ReplaceAllString(content, "")
	content = strings.TrimSpace(content)

	urls := urlRegexCompiled.FindAllString(content, -1)
	if len(urls) == 0 {
		return policy.ResponseChunkAction{} // no URLs — pass through
	}

	invalidURLs := make([]string, 0)
	for _, urlStr := range urls {
		var isValid bool
		if p.responseParams.OnlyDNS {
			isValid = p.checkDNS(urlStr, p.responseParams.Timeout)
		} else {
			isValid = p.checkURL(urlStr, p.responseParams.Timeout)
		}
		if !isValid {
			invalidURLs = append(invalidURLs, urlStr)
		}
	}

	if len(invalidURLs) > 0 {
		slog.Debug("URLGuardrail: streaming validation failed",
			"invalidURLCount", len(invalidURLs), "totalURLCount", len(urls))
		return policy.ResponseChunkAction{
			Body: p.buildSSEErrorEvent(invalidURLs, p.responseParams.ShowAssessment),
		}
	}

	return policy.ResponseChunkAction{} // all URLs valid — pass through
}

// extractSSEDeltaContent concatenates choices[*].delta.content values from
// every complete SSE data line in s. Returns "" for non-SSE content.
func extractSSEDeltaContent(s string) string {
	var sb strings.Builder
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, sseDataPrefix) {
			continue
		}
		jsonStr := strings.TrimPrefix(line, sseDataPrefix)
		if jsonStr == sseDone {
			continue
		}
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
			continue // partial or malformed line
		}
		choices, _ := data["choices"].([]interface{})
		for _, cr := range choices {
			choice, _ := cr.(map[string]interface{})
			delta, _ := choice["delta"].(map[string]interface{})
			content, _ := delta["content"].(string)
			sb.WriteString(content)
		}
	}
	return sb.String()
}

// buildSSEErrorEvent formats a guardrail intervention as a single SSE data
// event, replacing the offending chunk in the stream.
func (p *URLGuardrailPolicy) buildSSEErrorEvent(invalidURLs []string, showAssessment bool) []byte {
	assessment := p.buildAssessmentObject("Violation of url validity detected", nil, true, showAssessment, invalidURLs)
	responseBody := map[string]interface{}{
		"type":    "URL_GUARDRAIL",
		"message": assessment,
	}
	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"URL_GUARDRAIL","message":"Internal error"}`)
	}
	return []byte(sseDataPrefix + string(bodyBytes) + "\n\n")
}

// validatePayload validates URLs in payload
func (p *URLGuardrailPolicy) validatePayload(payload []byte, params URLGuardrailPolicyParams, isResponse bool) interface{} {
	// Extract value using JSONPath
	extractedValue, err := extractStringFromJSONPath(payload, params.JsonPath)
	if err != nil {
		slog.Debug("URLGuardrail: Error extracting value from JSONPath", "jsonPath", params.JsonPath, "error", err, "isResponse", isResponse)
		return p.buildErrorResponse("Error extracting value from JSONPath", err, isResponse, params.ShowAssessment, []string{})
	}

	// Clean and trim
	extractedValue = textCleanRegexCompiled.ReplaceAllString(extractedValue, "")
	extractedValue = strings.TrimSpace(extractedValue)

	// Extract URLs from the value
	urls := urlRegexCompiled.FindAllString(extractedValue, -1)
	if len(urls) > 0 {
		slog.Debug("URLGuardrail: Found URLs to validate", "urlCount", len(urls), "onlyDNS", params.OnlyDNS, "isResponse", isResponse)
	}
	invalidURLs := make([]string, 0)

	for _, urlStr := range urls {
		var isValid bool
		if params.OnlyDNS {
			isValid = p.checkDNS(urlStr, params.Timeout)
		} else {
			isValid = p.checkURL(urlStr, params.Timeout)
		}

		if !isValid {
			invalidURLs = append(invalidURLs, urlStr)
		}
	}

	if len(invalidURLs) > 0 {
		slog.Debug("URLGuardrail: Validation failed", "invalidURLCount", len(invalidURLs), "totalURLCount", len(urls), "isResponse", isResponse)
		return p.buildErrorResponse("Violation of url validity detected", nil, isResponse, params.ShowAssessment, invalidURLs)
	}

	if len(urls) > 0 {
		slog.Debug("URLGuardrail: Validation passed", "urlCount", len(urls), "isResponse", isResponse)
	}

	if isResponse {
		return policy.UpstreamResponseModifications{}
	}
	return policy.UpstreamRequestModifications{}
}

func extractStringFromJSONPath(payload []byte, jsonPath string) (string, error) {
	value, err := utils.ExtractStringValueFromJsonpath(payload, jsonPath)
	if err == nil {
		return value, nil
	}

	var jsonData map[string]interface{}
	if unmarshalErr := json.Unmarshal(payload, &jsonData); unmarshalErr != nil {
		return "", unmarshalErr
	}

	extracted, extractErr := utils.ExtractValueFromJsonpath(jsonData, jsonPath)
	if extractErr != nil {
		return "", extractErr
	}

	normalized, normalizeErr := normalizeExtractedValue(extracted)
	if normalizeErr != nil {
		return "", normalizeErr
	}

	return normalized, nil
}

func normalizeExtractedValue(value interface{}) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case float64, int, bool:
		return fmt.Sprint(v), nil
	case map[string]interface{}:
		if content, ok := v["content"]; ok {
			return normalizeExtractedValue(content)
		}
		if text, ok := v["text"]; ok {
			return normalizeExtractedValue(text)
		}
		encoded, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(encoded), nil
	case []interface{}:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			part, itemErr := normalizeExtractedValue(item)
			if itemErr != nil {
				continue
			}
			part = strings.TrimSpace(part)
			if part != "" {
				parts = append(parts, part)
			}
		}
		if len(parts) == 0 {
			return "", fmt.Errorf("value at JSONPath is an empty array")
		}
		return strings.Join(parts, " "), nil
	default:
		return "", fmt.Errorf("value at JSONPath is not a supported type")
	}
}

// checkDNS checks if the URL is resolved via DNS
func (p *URLGuardrailPolicy) checkDNS(target string, timeout int) bool {
	parsedURL, err := url.Parse(target)
	if err != nil {
		return false
	}

	host := parsedURL.Hostname()
	if host == "" {
		return false
	}

	// Create a custom resolver with timeout
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Duration(timeout) * time.Millisecond,
			}
			return d.DialContext(ctx, network, address)
		},
	}

	// Look up IP addresses
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()

	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return false
	}

	return len(ips) > 0
}

// checkURL checks if the URL is reachable via HTTP HEAD request
func (p *URLGuardrailPolicy) checkURL(target string, timeout int) bool {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Millisecond,
	}

	req, err := http.NewRequest("HEAD", target, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "URLValidator/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	statusCode := resp.StatusCode
	return statusCode >= 200 && statusCode < 400
}

// buildErrorResponse builds an error response for both request and response phases
func (p *URLGuardrailPolicy) buildErrorResponse(reason string, validationError error, isResponse bool, showAssessment bool, invalidURLs []string) interface{} {
	assessment := p.buildAssessmentObject(reason, validationError, isResponse, showAssessment, invalidURLs)

	responseBody := map[string]interface{}{
		"type":    "URL_GUARDRAIL",
		"message": assessment,
	}

	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"URL_GUARDRAIL","message":"Internal error"}`)
	}

	if isResponse {
		statusCode := GuardrailErrorCode
		return policy.UpstreamResponseModifications{
			StatusCode: &statusCode,
			Body:       bodyBytes,
			SetHeaders: map[string]string{
				"Content-Type": "application/json",
			},
		}
	}

	return policy.ImmediateResponse{
		StatusCode: GuardrailErrorCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: bodyBytes,
	}
}

// buildAssessmentObject builds the assessment object
func (p *URLGuardrailPolicy) buildAssessmentObject(reason string, validationError error, isResponse bool, showAssessment bool, invalidURLs []string) map[string]interface{} {
	assessment := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": "url-guardrail",
	}

	if isResponse {
		assessment["direction"] = "RESPONSE"
	} else {
		assessment["direction"] = "REQUEST"
	}

	if validationError != nil {
		assessment["actionReason"] = reason
	} else {
		assessment["actionReason"] = "Violation of url validity detected."
	}

	if showAssessment {
		if validationError != nil {
			assessment["assessments"] = validationError.Error()
		} else if len(invalidURLs) > 0 {
			assessmentDetails := map[string]interface{}{
				"message":     "One or more URLs in the payload failed validation.",
				"invalidUrls": invalidURLs,
			}
			assessment["assessments"] = assessmentDetails
		}
	}

	return assessment
}
