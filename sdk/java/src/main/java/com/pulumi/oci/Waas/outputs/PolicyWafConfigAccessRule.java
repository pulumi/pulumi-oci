// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Waas.outputs.PolicyWafConfigAccessRuleCriteria;
import com.pulumi.oci.Waas.outputs.PolicyWafConfigAccessRuleResponseHeaderManipulation;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class PolicyWafConfigAccessRule {
    /**
     * @return (Updatable) The action to take against requests from detected bots. If unspecified, defaults to `DETECT`.
     * 
     */
    private final String action;
    /**
     * @return (Updatable) If `action` is set to `BLOCK`, this specifies how the traffic is blocked when detected as malicious by a protection rule. If unspecified, defaults to `SET_RESPONSE_CODE`.
     * 
     */
    private final @Nullable String blockAction;
    /**
     * @return (Updatable) The error code to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`.
     * 
     */
    private final @Nullable String blockErrorPageCode;
    /**
     * @return (Updatable) The description text to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `Access blocked by website owner. Please contact support.`
     * 
     */
    private final @Nullable String blockErrorPageDescription;
    /**
     * @return (Updatable) The message to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to &#39;Access to the website is blocked.&#39;
     * 
     */
    private final @Nullable String blockErrorPageMessage;
    /**
     * @return (Updatable) The response code returned when `action` is set to `BLOCK`, `blockAction` is set to `SET_RESPONSE_CODE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`. The list of available response codes: `400`, `401`, `403`, `405`, `409`, `411`, `412`, `413`, `414`, `415`, `416`, `500`, `501`, `502`, `503`, `504`, `507`.
     * 
     */
    private final @Nullable Integer blockResponseCode;
    /**
     * @return (Updatable) The list of challenges to bypass when `action` is set to `BYPASS`. If unspecified or empty, all challenges are bypassed.
     * * **JS_CHALLENGE:** Bypasses JavaScript Challenge.
     * * **DEVICE_FINGERPRINT_CHALLENGE:** Bypasses Device Fingerprint Challenge.
     * * **HUMAN_INTERACTION_CHALLENGE:** Bypasses Human Interaction Challenge.
     * * **CAPTCHA:** Bypasses CAPTCHA Challenge.
     * 
     */
    private final @Nullable List<String> bypassChallenges;
    /**
     * @return (Updatable) The text to show in the footer when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, default to `Enter the letters and numbers as they are shown in image above`.
     * 
     */
    private final @Nullable String captchaFooter;
    /**
     * @return (Updatable) The text to show in the header when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `We have detected an increased number of attempts to access this webapp. To help us keep this webapp secure, please let us know that you are not a robot by entering the text from captcha below.`
     * 
     */
    private final @Nullable String captchaHeader;
    /**
     * @return (Updatable) The text to show on the label of the CAPTCHA challenge submit button when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `Yes, I am human`.
     * 
     */
    private final @Nullable String captchaSubmitLabel;
    /**
     * @return (Updatable) The title used when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `Are you human?`
     * 
     */
    private final @Nullable String captchaTitle;
    /**
     * @return (Updatable) When defined, the JavaScript Challenge would be applied only for the requests that matched all the listed conditions.
     * 
     */
    private final List<PolicyWafConfigAccessRuleCriteria> criterias;
    /**
     * @return (Updatable) The unique name of the whitelist.
     * 
     */
    private final String name;
    /**
     * @return (Updatable) The response status code to return when `action` is set to `REDIRECT`.
     * * **MOVED_PERMANENTLY:** Used for designating the permanent movement of a page (numerical code - 301).
     * * **FOUND:** Used for designating the temporary movement of a page (numerical code - 302).
     * 
     */
    private final @Nullable String redirectResponseCode;
    /**
     * @return (Updatable) The target to which the request should be redirected, represented as a URI reference. Required when `action` is `REDIRECT`.
     * 
     */
    private final @Nullable String redirectUrl;
    /**
     * @return (Updatable) An object that represents an action to apply to an HTTP response headers if all rule criteria will be matched regardless of `action` value.
     * 
     */
    private final @Nullable List<PolicyWafConfigAccessRuleResponseHeaderManipulation> responseHeaderManipulations;

    @CustomType.Constructor
    private PolicyWafConfigAccessRule(
        @CustomType.Parameter("action") String action,
        @CustomType.Parameter("blockAction") @Nullable String blockAction,
        @CustomType.Parameter("blockErrorPageCode") @Nullable String blockErrorPageCode,
        @CustomType.Parameter("blockErrorPageDescription") @Nullable String blockErrorPageDescription,
        @CustomType.Parameter("blockErrorPageMessage") @Nullable String blockErrorPageMessage,
        @CustomType.Parameter("blockResponseCode") @Nullable Integer blockResponseCode,
        @CustomType.Parameter("bypassChallenges") @Nullable List<String> bypassChallenges,
        @CustomType.Parameter("captchaFooter") @Nullable String captchaFooter,
        @CustomType.Parameter("captchaHeader") @Nullable String captchaHeader,
        @CustomType.Parameter("captchaSubmitLabel") @Nullable String captchaSubmitLabel,
        @CustomType.Parameter("captchaTitle") @Nullable String captchaTitle,
        @CustomType.Parameter("criterias") List<PolicyWafConfigAccessRuleCriteria> criterias,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("redirectResponseCode") @Nullable String redirectResponseCode,
        @CustomType.Parameter("redirectUrl") @Nullable String redirectUrl,
        @CustomType.Parameter("responseHeaderManipulations") @Nullable List<PolicyWafConfigAccessRuleResponseHeaderManipulation> responseHeaderManipulations) {
        this.action = action;
        this.blockAction = blockAction;
        this.blockErrorPageCode = blockErrorPageCode;
        this.blockErrorPageDescription = blockErrorPageDescription;
        this.blockErrorPageMessage = blockErrorPageMessage;
        this.blockResponseCode = blockResponseCode;
        this.bypassChallenges = bypassChallenges;
        this.captchaFooter = captchaFooter;
        this.captchaHeader = captchaHeader;
        this.captchaSubmitLabel = captchaSubmitLabel;
        this.captchaTitle = captchaTitle;
        this.criterias = criterias;
        this.name = name;
        this.redirectResponseCode = redirectResponseCode;
        this.redirectUrl = redirectUrl;
        this.responseHeaderManipulations = responseHeaderManipulations;
    }

    /**
     * @return (Updatable) The action to take against requests from detected bots. If unspecified, defaults to `DETECT`.
     * 
     */
    public String action() {
        return this.action;
    }
    /**
     * @return (Updatable) If `action` is set to `BLOCK`, this specifies how the traffic is blocked when detected as malicious by a protection rule. If unspecified, defaults to `SET_RESPONSE_CODE`.
     * 
     */
    public Optional<String> blockAction() {
        return Optional.ofNullable(this.blockAction);
    }
    /**
     * @return (Updatable) The error code to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`.
     * 
     */
    public Optional<String> blockErrorPageCode() {
        return Optional.ofNullable(this.blockErrorPageCode);
    }
    /**
     * @return (Updatable) The description text to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `Access blocked by website owner. Please contact support.`
     * 
     */
    public Optional<String> blockErrorPageDescription() {
        return Optional.ofNullable(this.blockErrorPageDescription);
    }
    /**
     * @return (Updatable) The message to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to &#39;Access to the website is blocked.&#39;
     * 
     */
    public Optional<String> blockErrorPageMessage() {
        return Optional.ofNullable(this.blockErrorPageMessage);
    }
    /**
     * @return (Updatable) The response code returned when `action` is set to `BLOCK`, `blockAction` is set to `SET_RESPONSE_CODE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`. The list of available response codes: `400`, `401`, `403`, `405`, `409`, `411`, `412`, `413`, `414`, `415`, `416`, `500`, `501`, `502`, `503`, `504`, `507`.
     * 
     */
    public Optional<Integer> blockResponseCode() {
        return Optional.ofNullable(this.blockResponseCode);
    }
    /**
     * @return (Updatable) The list of challenges to bypass when `action` is set to `BYPASS`. If unspecified or empty, all challenges are bypassed.
     * * **JS_CHALLENGE:** Bypasses JavaScript Challenge.
     * * **DEVICE_FINGERPRINT_CHALLENGE:** Bypasses Device Fingerprint Challenge.
     * * **HUMAN_INTERACTION_CHALLENGE:** Bypasses Human Interaction Challenge.
     * * **CAPTCHA:** Bypasses CAPTCHA Challenge.
     * 
     */
    public List<String> bypassChallenges() {
        return this.bypassChallenges == null ? List.of() : this.bypassChallenges;
    }
    /**
     * @return (Updatable) The text to show in the footer when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, default to `Enter the letters and numbers as they are shown in image above`.
     * 
     */
    public Optional<String> captchaFooter() {
        return Optional.ofNullable(this.captchaFooter);
    }
    /**
     * @return (Updatable) The text to show in the header when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `We have detected an increased number of attempts to access this webapp. To help us keep this webapp secure, please let us know that you are not a robot by entering the text from captcha below.`
     * 
     */
    public Optional<String> captchaHeader() {
        return Optional.ofNullable(this.captchaHeader);
    }
    /**
     * @return (Updatable) The text to show on the label of the CAPTCHA challenge submit button when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `Yes, I am human`.
     * 
     */
    public Optional<String> captchaSubmitLabel() {
        return Optional.ofNullable(this.captchaSubmitLabel);
    }
    /**
     * @return (Updatable) The title used when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `Are you human?`
     * 
     */
    public Optional<String> captchaTitle() {
        return Optional.ofNullable(this.captchaTitle);
    }
    /**
     * @return (Updatable) When defined, the JavaScript Challenge would be applied only for the requests that matched all the listed conditions.
     * 
     */
    public List<PolicyWafConfigAccessRuleCriteria> criterias() {
        return this.criterias;
    }
    /**
     * @return (Updatable) The unique name of the whitelist.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return (Updatable) The response status code to return when `action` is set to `REDIRECT`.
     * * **MOVED_PERMANENTLY:** Used for designating the permanent movement of a page (numerical code - 301).
     * * **FOUND:** Used for designating the temporary movement of a page (numerical code - 302).
     * 
     */
    public Optional<String> redirectResponseCode() {
        return Optional.ofNullable(this.redirectResponseCode);
    }
    /**
     * @return (Updatable) The target to which the request should be redirected, represented as a URI reference. Required when `action` is `REDIRECT`.
     * 
     */
    public Optional<String> redirectUrl() {
        return Optional.ofNullable(this.redirectUrl);
    }
    /**
     * @return (Updatable) An object that represents an action to apply to an HTTP response headers if all rule criteria will be matched regardless of `action` value.
     * 
     */
    public List<PolicyWafConfigAccessRuleResponseHeaderManipulation> responseHeaderManipulations() {
        return this.responseHeaderManipulations == null ? List.of() : this.responseHeaderManipulations;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(PolicyWafConfigAccessRule defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String action;
        private @Nullable String blockAction;
        private @Nullable String blockErrorPageCode;
        private @Nullable String blockErrorPageDescription;
        private @Nullable String blockErrorPageMessage;
        private @Nullable Integer blockResponseCode;
        private @Nullable List<String> bypassChallenges;
        private @Nullable String captchaFooter;
        private @Nullable String captchaHeader;
        private @Nullable String captchaSubmitLabel;
        private @Nullable String captchaTitle;
        private List<PolicyWafConfigAccessRuleCriteria> criterias;
        private String name;
        private @Nullable String redirectResponseCode;
        private @Nullable String redirectUrl;
        private @Nullable List<PolicyWafConfigAccessRuleResponseHeaderManipulation> responseHeaderManipulations;

        public Builder() {
    	      // Empty
        }

        public Builder(PolicyWafConfigAccessRule defaults) {
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

        public Builder action(String action) {
            this.action = Objects.requireNonNull(action);
            return this;
        }
        public Builder blockAction(@Nullable String blockAction) {
            this.blockAction = blockAction;
            return this;
        }
        public Builder blockErrorPageCode(@Nullable String blockErrorPageCode) {
            this.blockErrorPageCode = blockErrorPageCode;
            return this;
        }
        public Builder blockErrorPageDescription(@Nullable String blockErrorPageDescription) {
            this.blockErrorPageDescription = blockErrorPageDescription;
            return this;
        }
        public Builder blockErrorPageMessage(@Nullable String blockErrorPageMessage) {
            this.blockErrorPageMessage = blockErrorPageMessage;
            return this;
        }
        public Builder blockResponseCode(@Nullable Integer blockResponseCode) {
            this.blockResponseCode = blockResponseCode;
            return this;
        }
        public Builder bypassChallenges(@Nullable List<String> bypassChallenges) {
            this.bypassChallenges = bypassChallenges;
            return this;
        }
        public Builder bypassChallenges(String... bypassChallenges) {
            return bypassChallenges(List.of(bypassChallenges));
        }
        public Builder captchaFooter(@Nullable String captchaFooter) {
            this.captchaFooter = captchaFooter;
            return this;
        }
        public Builder captchaHeader(@Nullable String captchaHeader) {
            this.captchaHeader = captchaHeader;
            return this;
        }
        public Builder captchaSubmitLabel(@Nullable String captchaSubmitLabel) {
            this.captchaSubmitLabel = captchaSubmitLabel;
            return this;
        }
        public Builder captchaTitle(@Nullable String captchaTitle) {
            this.captchaTitle = captchaTitle;
            return this;
        }
        public Builder criterias(List<PolicyWafConfigAccessRuleCriteria> criterias) {
            this.criterias = Objects.requireNonNull(criterias);
            return this;
        }
        public Builder criterias(PolicyWafConfigAccessRuleCriteria... criterias) {
            return criterias(List.of(criterias));
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder redirectResponseCode(@Nullable String redirectResponseCode) {
            this.redirectResponseCode = redirectResponseCode;
            return this;
        }
        public Builder redirectUrl(@Nullable String redirectUrl) {
            this.redirectUrl = redirectUrl;
            return this;
        }
        public Builder responseHeaderManipulations(@Nullable List<PolicyWafConfigAccessRuleResponseHeaderManipulation> responseHeaderManipulations) {
            this.responseHeaderManipulations = responseHeaderManipulations;
            return this;
        }
        public Builder responseHeaderManipulations(PolicyWafConfigAccessRuleResponseHeaderManipulation... responseHeaderManipulations) {
            return responseHeaderManipulations(List.of(responseHeaderManipulations));
        }        public PolicyWafConfigAccessRule build() {
            return new PolicyWafConfigAccessRule(action, blockAction, blockErrorPageCode, blockErrorPageDescription, blockErrorPageMessage, blockResponseCode, bypassChallenges, captchaFooter, captchaHeader, captchaSubmitLabel, captchaTitle, criterias, name, redirectResponseCode, redirectUrl, responseHeaderManipulations);
        }
    }
}
