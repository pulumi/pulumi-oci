// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Waas.outputs.GetWaasPolicyWafConfigAccessRuleCriteria;
import com.pulumi.oci.Waas.outputs.GetWaasPolicyWafConfigAccessRuleResponseHeaderManipulation;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetWaasPolicyWafConfigAccessRule {
    /**
     * @return The action to take against requests from detected bots. If unspecified, defaults to `DETECT`.
     * 
     */
    private String action;
    /**
     * @return If `action` is set to `BLOCK`, this specifies how the traffic is blocked when detected as malicious by a protection rule. If unspecified, defaults to `SET_RESPONSE_CODE`.
     * 
     */
    private String blockAction;
    /**
     * @return The error code to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`.
     * 
     */
    private String blockErrorPageCode;
    /**
     * @return The description text to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `Access blocked by website owner. Please contact support.`
     * 
     */
    private String blockErrorPageDescription;
    /**
     * @return The message to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to &#39;Access to the website is blocked.&#39;
     * 
     */
    private String blockErrorPageMessage;
    /**
     * @return The response code returned when `action` is set to `BLOCK`, `blockAction` is set to `SET_RESPONSE_CODE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`. The list of available response codes: `400`, `401`, `403`, `405`, `409`, `411`, `412`, `413`, `414`, `415`, `416`, `500`, `501`, `502`, `503`, `504`, `507`.
     * 
     */
    private Integer blockResponseCode;
    /**
     * @return The list of challenges to bypass when `action` is set to `BYPASS`. If unspecified or empty, all challenges are bypassed.
     * * **JS_CHALLENGE:** Bypasses JavaScript Challenge.
     * * **DEVICE_FINGERPRINT_CHALLENGE:** Bypasses Device Fingerprint Challenge.
     * * **HUMAN_INTERACTION_CHALLENGE:** Bypasses Human Interaction Challenge.
     * * **CAPTCHA:** Bypasses CAPTCHA Challenge.
     * 
     */
    private List<String> bypassChallenges;
    /**
     * @return The text to show in the footer when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, default to `Enter the letters and numbers as they are shown in image above`.
     * 
     */
    private String captchaFooter;
    /**
     * @return The text to show in the header when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `We have detected an increased number of attempts to access this webapp. To help us keep this webapp secure, please let us know that you are not a robot by entering the text from captcha below.`
     * 
     */
    private String captchaHeader;
    /**
     * @return The text to show on the label of the CAPTCHA challenge submit button when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `Yes, I am human`.
     * 
     */
    private String captchaSubmitLabel;
    /**
     * @return The title used when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `Are you human?`
     * 
     */
    private String captchaTitle;
    /**
     * @return When defined, the JavaScript Challenge would be applied only for the requests that matched all the listed conditions.
     * 
     */
    private List<GetWaasPolicyWafConfigAccessRuleCriteria> criterias;
    /**
     * @return The unique name of the whitelist.
     * 
     */
    private String name;
    /**
     * @return The response status code to return when `action` is set to `REDIRECT`.
     * * **MOVED_PERMANENTLY:** Used for designating the permanent movement of a page (numerical code - 301).
     * * **FOUND:** Used for designating the temporary movement of a page (numerical code - 302).
     * 
     */
    private String redirectResponseCode;
    /**
     * @return The target to which the request should be redirected, represented as a URI reference. Required when `action` is `REDIRECT`.
     * 
     */
    private String redirectUrl;
    /**
     * @return An object that represents an action to apply to an HTTP response headers if all rule criteria will be matched regardless of `action` value.
     * 
     */
    private List<GetWaasPolicyWafConfigAccessRuleResponseHeaderManipulation> responseHeaderManipulations;

    private GetWaasPolicyWafConfigAccessRule() {}
    /**
     * @return The action to take against requests from detected bots. If unspecified, defaults to `DETECT`.
     * 
     */
    public String action() {
        return this.action;
    }
    /**
     * @return If `action` is set to `BLOCK`, this specifies how the traffic is blocked when detected as malicious by a protection rule. If unspecified, defaults to `SET_RESPONSE_CODE`.
     * 
     */
    public String blockAction() {
        return this.blockAction;
    }
    /**
     * @return The error code to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`.
     * 
     */
    public String blockErrorPageCode() {
        return this.blockErrorPageCode;
    }
    /**
     * @return The description text to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `Access blocked by website owner. Please contact support.`
     * 
     */
    public String blockErrorPageDescription() {
        return this.blockErrorPageDescription;
    }
    /**
     * @return The message to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to &#39;Access to the website is blocked.&#39;
     * 
     */
    public String blockErrorPageMessage() {
        return this.blockErrorPageMessage;
    }
    /**
     * @return The response code returned when `action` is set to `BLOCK`, `blockAction` is set to `SET_RESPONSE_CODE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`. The list of available response codes: `400`, `401`, `403`, `405`, `409`, `411`, `412`, `413`, `414`, `415`, `416`, `500`, `501`, `502`, `503`, `504`, `507`.
     * 
     */
    public Integer blockResponseCode() {
        return this.blockResponseCode;
    }
    /**
     * @return The list of challenges to bypass when `action` is set to `BYPASS`. If unspecified or empty, all challenges are bypassed.
     * * **JS_CHALLENGE:** Bypasses JavaScript Challenge.
     * * **DEVICE_FINGERPRINT_CHALLENGE:** Bypasses Device Fingerprint Challenge.
     * * **HUMAN_INTERACTION_CHALLENGE:** Bypasses Human Interaction Challenge.
     * * **CAPTCHA:** Bypasses CAPTCHA Challenge.
     * 
     */
    public List<String> bypassChallenges() {
        return this.bypassChallenges;
    }
    /**
     * @return The text to show in the footer when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, default to `Enter the letters and numbers as they are shown in image above`.
     * 
     */
    public String captchaFooter() {
        return this.captchaFooter;
    }
    /**
     * @return The text to show in the header when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `We have detected an increased number of attempts to access this webapp. To help us keep this webapp secure, please let us know that you are not a robot by entering the text from captcha below.`
     * 
     */
    public String captchaHeader() {
        return this.captchaHeader;
    }
    /**
     * @return The text to show on the label of the CAPTCHA challenge submit button when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `Yes, I am human`.
     * 
     */
    public String captchaSubmitLabel() {
        return this.captchaSubmitLabel;
    }
    /**
     * @return The title used when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `Are you human?`
     * 
     */
    public String captchaTitle() {
        return this.captchaTitle;
    }
    /**
     * @return When defined, the JavaScript Challenge would be applied only for the requests that matched all the listed conditions.
     * 
     */
    public List<GetWaasPolicyWafConfigAccessRuleCriteria> criterias() {
        return this.criterias;
    }
    /**
     * @return The unique name of the whitelist.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The response status code to return when `action` is set to `REDIRECT`.
     * * **MOVED_PERMANENTLY:** Used for designating the permanent movement of a page (numerical code - 301).
     * * **FOUND:** Used for designating the temporary movement of a page (numerical code - 302).
     * 
     */
    public String redirectResponseCode() {
        return this.redirectResponseCode;
    }
    /**
     * @return The target to which the request should be redirected, represented as a URI reference. Required when `action` is `REDIRECT`.
     * 
     */
    public String redirectUrl() {
        return this.redirectUrl;
    }
    /**
     * @return An object that represents an action to apply to an HTTP response headers if all rule criteria will be matched regardless of `action` value.
     * 
     */
    public List<GetWaasPolicyWafConfigAccessRuleResponseHeaderManipulation> responseHeaderManipulations() {
        return this.responseHeaderManipulations;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWaasPolicyWafConfigAccessRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String action;
        private String blockAction;
        private String blockErrorPageCode;
        private String blockErrorPageDescription;
        private String blockErrorPageMessage;
        private Integer blockResponseCode;
        private List<String> bypassChallenges;
        private String captchaFooter;
        private String captchaHeader;
        private String captchaSubmitLabel;
        private String captchaTitle;
        private List<GetWaasPolicyWafConfigAccessRuleCriteria> criterias;
        private String name;
        private String redirectResponseCode;
        private String redirectUrl;
        private List<GetWaasPolicyWafConfigAccessRuleResponseHeaderManipulation> responseHeaderManipulations;
        public Builder() {}
        public Builder(GetWaasPolicyWafConfigAccessRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.action = defaults.action;
    	      this.blockAction = defaults.blockAction;
    	      this.blockErrorPageCode = defaults.blockErrorPageCode;
    	      this.blockErrorPageDescription = defaults.blockErrorPageDescription;
    	      this.blockErrorPageMessage = defaults.blockErrorPageMessage;
    	      this.blockResponseCode = defaults.blockResponseCode;
    	      this.bypassChallenges = defaults.bypassChallenges;
    	      this.captchaFooter = defaults.captchaFooter;
    	      this.captchaHeader = defaults.captchaHeader;
    	      this.captchaSubmitLabel = defaults.captchaSubmitLabel;
    	      this.captchaTitle = defaults.captchaTitle;
    	      this.criterias = defaults.criterias;
    	      this.name = defaults.name;
    	      this.redirectResponseCode = defaults.redirectResponseCode;
    	      this.redirectUrl = defaults.redirectUrl;
    	      this.responseHeaderManipulations = defaults.responseHeaderManipulations;
        }

        @CustomType.Setter
        public Builder action(String action) {
            this.action = Objects.requireNonNull(action);
            return this;
        }
        @CustomType.Setter
        public Builder blockAction(String blockAction) {
            this.blockAction = Objects.requireNonNull(blockAction);
            return this;
        }
        @CustomType.Setter
        public Builder blockErrorPageCode(String blockErrorPageCode) {
            this.blockErrorPageCode = Objects.requireNonNull(blockErrorPageCode);
            return this;
        }
        @CustomType.Setter
        public Builder blockErrorPageDescription(String blockErrorPageDescription) {
            this.blockErrorPageDescription = Objects.requireNonNull(blockErrorPageDescription);
            return this;
        }
        @CustomType.Setter
        public Builder blockErrorPageMessage(String blockErrorPageMessage) {
            this.blockErrorPageMessage = Objects.requireNonNull(blockErrorPageMessage);
            return this;
        }
        @CustomType.Setter
        public Builder blockResponseCode(Integer blockResponseCode) {
            this.blockResponseCode = Objects.requireNonNull(blockResponseCode);
            return this;
        }
        @CustomType.Setter
        public Builder bypassChallenges(List<String> bypassChallenges) {
            this.bypassChallenges = Objects.requireNonNull(bypassChallenges);
            return this;
        }
        public Builder bypassChallenges(String... bypassChallenges) {
            return bypassChallenges(List.of(bypassChallenges));
        }
        @CustomType.Setter
        public Builder captchaFooter(String captchaFooter) {
            this.captchaFooter = Objects.requireNonNull(captchaFooter);
            return this;
        }
        @CustomType.Setter
        public Builder captchaHeader(String captchaHeader) {
            this.captchaHeader = Objects.requireNonNull(captchaHeader);
            return this;
        }
        @CustomType.Setter
        public Builder captchaSubmitLabel(String captchaSubmitLabel) {
            this.captchaSubmitLabel = Objects.requireNonNull(captchaSubmitLabel);
            return this;
        }
        @CustomType.Setter
        public Builder captchaTitle(String captchaTitle) {
            this.captchaTitle = Objects.requireNonNull(captchaTitle);
            return this;
        }
        @CustomType.Setter
        public Builder criterias(List<GetWaasPolicyWafConfigAccessRuleCriteria> criterias) {
            this.criterias = Objects.requireNonNull(criterias);
            return this;
        }
        public Builder criterias(GetWaasPolicyWafConfigAccessRuleCriteria... criterias) {
            return criterias(List.of(criterias));
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder redirectResponseCode(String redirectResponseCode) {
            this.redirectResponseCode = Objects.requireNonNull(redirectResponseCode);
            return this;
        }
        @CustomType.Setter
        public Builder redirectUrl(String redirectUrl) {
            this.redirectUrl = Objects.requireNonNull(redirectUrl);
            return this;
        }
        @CustomType.Setter
        public Builder responseHeaderManipulations(List<GetWaasPolicyWafConfigAccessRuleResponseHeaderManipulation> responseHeaderManipulations) {
            this.responseHeaderManipulations = Objects.requireNonNull(responseHeaderManipulations);
            return this;
        }
        public Builder responseHeaderManipulations(GetWaasPolicyWafConfigAccessRuleResponseHeaderManipulation... responseHeaderManipulations) {
            return responseHeaderManipulations(List.of(responseHeaderManipulations));
        }
        public GetWaasPolicyWafConfigAccessRule build() {
            final var o = new GetWaasPolicyWafConfigAccessRule();
            o.action = action;
            o.blockAction = blockAction;
            o.blockErrorPageCode = blockErrorPageCode;
            o.blockErrorPageDescription = blockErrorPageDescription;
            o.blockErrorPageMessage = blockErrorPageMessage;
            o.blockResponseCode = blockResponseCode;
            o.bypassChallenges = bypassChallenges;
            o.captchaFooter = captchaFooter;
            o.captchaHeader = captchaHeader;
            o.captchaSubmitLabel = captchaSubmitLabel;
            o.captchaTitle = captchaTitle;
            o.criterias = criterias;
            o.name = name;
            o.redirectResponseCode = redirectResponseCode;
            o.redirectUrl = redirectUrl;
            o.responseHeaderManipulations = responseHeaderManipulations;
            return o;
        }
    }
}