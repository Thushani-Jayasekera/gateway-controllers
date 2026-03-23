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

package regexguardrail

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
	utils "github.com/wso2/api-platform/sdk/utils"
)

const (
	GuardrailErrorCode           = 422
	DefaultRequestJSONPath       = "$.messages[-1].content"
	DefaultResponseJSONPath      = "$.choices[0].message.content"
	RequestFlowEnabledByDefault  = true
	ResponseFlowEnabledByDefault = false

	sseDataPrefix                    = "data: "
	sseDone                          = "[DONE]"
	metaKeyAccumulatedResponseContent = "regexguardrail:accumulated_response_content"
)

// RegexGuardrailPolicy implements regex-based content validation
type RegexGuardrailPolicy struct {
	hasRequestParams  bool
	hasResponseParams bool
	requestParams     RegexGuardrailPolicyParams
	responseParams    RegexGuardrailPolicyParams
}

type RegexGuardrailPolicyParams struct {
	Enabled        bool
	Regex          string
	JsonPath       string
	Invert         bool
	ShowAssessment bool
}

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &RegexGuardrailPolicy{}

	// Extract and parse request parameters if present
	if requestParamsRaw, ok := params["request"].(map[string]interface{}); ok {
		requestParams, err := parseParams(requestParamsRaw, DefaultRequestJSONPath, RequestFlowEnabledByDefault)
		if err != nil {
			return nil, fmt.Errorf("invalid request parameters: %w", err)
		}
		p.hasRequestParams = true
		p.requestParams = requestParams
	}

	// Extract and parse response parameters if present
	if responseParamsRaw, ok := params["response"].(map[string]interface{}); ok {
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

	slog.Debug("RegexGuardrail: Policy initialized", "hasRequestParams", p.hasRequestParams, "hasResponseParams", p.hasResponseParams)

	return p, nil
}

// parseParams parses and validates parameters from map to struct
func parseParams(params map[string]interface{}, defaultJSONPath string, defaultEnabled bool) (RegexGuardrailPolicyParams, error) {
	result := RegexGuardrailPolicyParams{
		Enabled:        defaultEnabled,
		JsonPath:       defaultJSONPath,
		Invert:         false,
		ShowAssessment: false,
	}
	enabledExplicitlyFalse := false

	// Extract optional enabled parameter
	if enabledRaw, ok := params["enabled"]; ok {
		enabled, ok := enabledRaw.(bool)
		if !ok {
			return result, fmt.Errorf("'enabled' must be a boolean")
		}
		result.Enabled = enabled
		enabledExplicitlyFalse = !enabled
	}

	regexRaw, hasRegex := params["regex"]
	if !enabledExplicitlyFalse && !hasRegex {
		return result, fmt.Errorf("'regex' parameter is required")
	}

	if hasRegex {
		regexPattern, ok := regexRaw.(string)
		if !ok {
			return result, fmt.Errorf("'regex' must be a string")
		}
		if regexPattern == "" {
			return result, fmt.Errorf("'regex' cannot be empty")
		}

		// Validate regex is compilable
		_, err := regexp.Compile(regexPattern)
		if err != nil {
			return result, fmt.Errorf("invalid regex pattern: %w", err)
		}
		result.Regex = regexPattern
	}

	// Extract optional jsonPath parameter
	if jsonPathRaw, ok := params["jsonPath"]; ok {
		if jsonPath, ok := jsonPathRaw.(string); ok {
			result.JsonPath = jsonPath
		} else {
			return result, fmt.Errorf("'jsonPath' must be a string")
		}
	}

	// Extract optional invert parameter
	if invertRaw, ok := params["invert"]; ok {
		if invert, ok := invertRaw.(bool); ok {
			result.Invert = invert
		} else {
			return result, fmt.Errorf("'invert' must be a boolean")
		}
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

// Mode returns the processing mode for this policy
func (p *RegexGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer, // Need full body for validation
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer, // Need full body for validation
	}
}

// OnRequest delegates to OnRequestBody for v1alpha engine compatibility.
func (p *RegexGuardrailPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	return p.OnRequestBody(ctx)
}

// OnRequestBody validates request body against regex pattern.
func (p *RegexGuardrailPolicy) OnRequestBody(ctx *policy.RequestContext) policy.RequestAction {
	if !p.hasRequestParams || !p.requestParams.Enabled {
		return policy.UpstreamRequestModifications{}
	}

	var content []byte
	if ctx.Body != nil {
		content = ctx.Body.Content
	}
	return p.validatePayload(content, p.requestParams, false).(policy.RequestAction)
}

// OnResponse delegates to OnResponseBody for v1alpha engine compatibility.
func (p *RegexGuardrailPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	return p.OnResponseBody(ctx)
}

// OnResponseBody validates response body against regex pattern.
func (p *RegexGuardrailPolicy) OnResponseBody(ctx *policy.ResponseContext) policy.ResponseAction {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return policy.UpstreamResponseModifications{}
	}

	var content []byte
	if ctx.ResponseBody != nil {
		content = ctx.ResponseBody.Content
	}
	return p.validatePayload(content, p.responseParams, true).(policy.ResponseAction)
}

// validatePayload validates payload against regex pattern
func (p *RegexGuardrailPolicy) validatePayload(payload []byte, params RegexGuardrailPolicyParams, isResponse bool) interface{} {
	// Nothing to validate (avoid blocking no-body requests / 204 responses)
	if len(payload) == 0 {
		if isResponse {
			return policy.UpstreamResponseModifications{}
		}
		return policy.UpstreamRequestModifications{}
	}
	// Extract value using JSONPath
	extractedValue, err := utils.ExtractStringValueFromJsonpath(payload, params.JsonPath)
	if err != nil {
		slog.Debug("RegexGuardrail: Error extracting value from JSONPath", "jsonPath", params.JsonPath, "error", err, "isResponse", isResponse)
		return p.buildErrorResponse("Error extracting value from JSONPath", err, isResponse, params.ShowAssessment)
	}

	// Compile regex pattern
	compiledRegex, err := regexp.Compile(params.Regex)
	if err != nil {
		slog.Debug("RegexGuardrail: Invalid regex pattern", "regex", params.Regex, "error", err, "isResponse", isResponse)
		return p.buildErrorResponse("Invalid regex pattern", err, isResponse, params.ShowAssessment)
	}
	matched := compiledRegex.MatchString(extractedValue)

	// Apply inversion logic
	var validationPassed bool
	if params.Invert {
		validationPassed = !matched // Inverted: pass if NOT matched
	} else {
		validationPassed = matched // Normal: pass if matched
	}

	if !validationPassed {
		slog.Debug("RegexGuardrail: Validation failed", "regex", params.Regex, "matched", matched, "invert", params.Invert, "isResponse", isResponse)
		return p.buildErrorResponse("Violated regular expression: "+params.Regex, nil, isResponse, params.ShowAssessment)
	}

	slog.Debug("RegexGuardrail: Validation passed", "regex", params.Regex, "matched", matched, "invert", params.Invert, "isResponse", isResponse)

	if isResponse {
		return policy.UpstreamResponseModifications{}
	}
	return policy.UpstreamRequestModifications{}
}

// buildErrorResponse builds an error response for both request and response phases
func (p *RegexGuardrailPolicy) buildErrorResponse(reason string, validationError error, isResponse bool, showAssessment bool) interface{} {
	assessment := p.buildAssessmentObject(reason, validationError, isResponse, showAssessment)

	responseBody := map[string]interface{}{
		"type":    "REGEX_GUARDRAIL",
		"message": assessment,
	}

	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"REGEX_GUARDRAIL","message":"Internal error"}`)
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

// ─── Streaming (SSE) support ──────────────────────────────────────────────────
//
// NeedsMoreResponseData and OnResponseBodyChunk together implement
// StreamingResponsePolicy for SSE (stream: true) responses.
//
// Cross-chunk matching: regex patterns can span token boundaries
// (e.g. "forbidden phrase" split across two SSE events). The accumulated
// delta.content is stored in ctx.Metadata so every chunk sees the full text
// seen so far, making cross-boundary matches detectable without inter-chunk
// buffering in NeedsMoreResponseData.
//
// Invert semantics in streaming:
//   - invert=true  (blocklist): violation detected as soon as the pattern
//     appears anywhere in the accumulated content; the offending chunk is
//     replaced with an SSE error event.
//   - invert=false (allowlist): the full response must match the pattern.
//     We can only confirm this at stream end ([DONE]), so an SSE error event
//     is injected at the terminal chunk if no match was found. Content
//     already forwarded to the client cannot be retracted — this is an
//     inherent limitation of response streaming.

// NeedsMoreResponseData implements StreamingResponsePolicy.
// Returns false for every chunk: cross-chunk accumulation is handled via
// ctx.Metadata rather than kernel-level buffering, keeping each SSE event
// flowing to the client without delay.
func (p *RegexGuardrailPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	return false
}

// OnResponseBodyChunk implements StreamingResponsePolicy.
// Validates SSE delta.content against the configured regex pattern,
// accumulating content across chunks so patterns split across token
// boundaries are still caught.
func (p *RegexGuardrailPolicy) OnResponseBodyChunk(ctx *policy.ResponseStreamContext, chunk *policy.StreamBody, params map[string]interface{}) policy.ResponseChunkAction {
	if !p.hasResponseParams || !p.responseParams.Enabled {
		return policy.ResponseChunkAction{}
	}
	if chunk == nil || len(chunk.Chunk) == 0 {
		return policy.ResponseChunkAction{}
	}

	chunkStr := string(chunk.Chunk)
	if !isSSEChunk(chunkStr) {
		// Non-SSE chunks (e.g. plain JSON via chunked transfer) pass through;
		// the buffered OnResponseBody handles them when the kernel buffers.
		return policy.ResponseChunkAction{}
	}

	rp := p.responseParams

	// Accumulate delta.content from this chunk into the running total.
	prev := ""
	if v, ok := ctx.Metadata[metaKeyAccumulatedResponseContent]; ok {
		if s, ok := v.(string); ok {
			prev = s
		}
	}
	chunkContent := extractSSEDeltaContent(chunkStr)
	accumulated := prev + chunkContent
	ctx.Metadata[metaKeyAccumulatedResponseContent] = accumulated

	compiledRegex, err := regexp.Compile(rp.Regex)
	if err != nil {
		// Invalid regex — pass through; the buffered path already caught this.
		return policy.ResponseChunkAction{}
	}

	matched := compiledRegex.MatchString(accumulated)
	isDone := strings.Contains(chunkStr, sseDataPrefix+sseDone)

	var violated bool
	if rp.Invert {
		// Blocklist: fail as soon as the prohibited pattern appears.
		violated = matched
	} else {
		// Allowlist: the content must match by the time the stream ends.
		// Intermediate chunks cannot be validated (match may come later).
		if isDone && accumulated != "" {
			violated = !matched
		}
	}

	if violated {
		slog.Debug("RegexGuardrail: streaming validation failed",
			"regex", rp.Regex, "invert", rp.Invert, "chunkIndex", chunk.Index)
		return policy.ResponseChunkAction{Body: p.buildSSEErrorEvent(rp)}
	}

	return policy.ResponseChunkAction{}
}

// isSSEChunk reports whether s contains at least one "data: " SSE line.
func isSSEChunk(s string) bool {
	for _, line := range strings.SplitN(s, "\n", 5) {
		if strings.HasPrefix(line, sseDataPrefix) {
			return true
		}
	}
	return false
}

// extractSSEDeltaContent concatenates choices[*].delta.content values from
// every complete SSE data line in s. Returns "" for non-SSE or empty content.
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
			continue // partial or malformed line — skip
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
// event, replacing the offending chunk in the stream. ImmediateResponse is
// not available once response headers are committed.
func (p *RegexGuardrailPolicy) buildSSEErrorEvent(rp RegexGuardrailPolicyParams) []byte {
	assessment := p.buildAssessmentObject("Violated regular expression: "+rp.Regex, nil, true, rp.ShowAssessment)
	responseBody := map[string]interface{}{
		"type":    "REGEX_GUARDRAIL",
		"message": assessment,
	}
	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(`{"type":"REGEX_GUARDRAIL","message":"Internal error"}`)
	}
	return []byte(sseDataPrefix + string(bodyBytes) + "\n\n")
}

// buildAssessmentObject builds the assessment object
func (p *RegexGuardrailPolicy) buildAssessmentObject(reason string, validationError error, isResponse bool, showAssessment bool) map[string]interface{} {
	assessment := map[string]interface{}{
		"action":               "GUARDRAIL_INTERVENED",
		"interveningGuardrail": "regex-guardrail",
	}

	if isResponse {
		assessment["direction"] = "RESPONSE"
	} else {
		assessment["direction"] = "REQUEST"
	}

	if validationError != nil {
		assessment["actionReason"] = reason
	} else {
		assessment["actionReason"] = "Violation of regular expression detected."
	}

	if showAssessment {
		if validationError != nil {
			assessment["assessments"] = validationError.Error()
		} else {
			var assessmentMessage string
			assessmentMessage = fmt.Sprintf("Violation of regular expression detected. %s", reason)
			assessment["assessments"] = assessmentMessage
		}
	}

	return assessment
}
