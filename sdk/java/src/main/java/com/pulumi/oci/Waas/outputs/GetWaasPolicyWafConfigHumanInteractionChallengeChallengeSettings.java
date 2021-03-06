// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetWaasPolicyWafConfigHumanInteractionChallengeChallengeSettings {
    /**
     * @return If `action` is set to `BLOCK`, this specifies how the traffic is blocked when detected as malicious by a protection rule. If unspecified, defaults to `SET_RESPONSE_CODE`.
     * 
     */
    private final String blockAction;
    /**
     * @return The error code to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`.
     * 
     */
    private final String blockErrorPageCode;
    /**
     * @return The description text to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `Access blocked by website owner. Please contact support.`
     * 
     */
    private final String blockErrorPageDescription;
    /**
     * @return The message to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to &#39;Access to the website is blocked.&#39;
     * 
     */
    private final String blockErrorPageMessage;
    /**
     * @return The response code returned when `action` is set to `BLOCK`, `blockAction` is set to `SET_RESPONSE_CODE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`. The list of available response codes: `400`, `401`, `403`, `405`, `409`, `411`, `412`, `413`, `414`, `415`, `416`, `500`, `501`, `502`, `503`, `504`, `507`.
     * 
     */
    private final Integer blockResponseCode;
    /**
     * @return The text to show in the footer when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, default to `Enter the letters and numbers as they are shown in image above`.
     * 
     */
    private final String captchaFooter;
    /**
     * @return The text to show in the header when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `We have detected an increased number of attempts to access this webapp. To help us keep this webapp secure, please let us know that you are not a robot by entering the text from captcha below.`
     * 
     */
    private final String captchaHeader;
    /**
     * @return The text to show on the label of the CAPTCHA challenge submit button when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `Yes, I am human`.
     * 
     */
    private final String captchaSubmitLabel;
    /**
     * @return The title used when showing a CAPTCHA challenge when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_CAPTCHA`, and the request is blocked. If unspecified, defaults to `Are you human?`
     * 
     */
    private final String captchaTitle;

    @CustomType.Constructor
    private GetWaasPolicyWafConfigHumanInteractionChallengeChallengeSettings(
        @CustomType.Parameter("blockAction") String blockAction,
        @CustomType.Parameter("blockErrorPageCode") String blockErrorPageCode,
        @CustomType.Parameter("blockErrorPageDescription") String blockErrorPageDescription,
        @CustomType.Parameter("blockErrorPageMessage") String blockErrorPageMessage,
        @CustomType.Parameter("blockResponseCode") Integer blockResponseCode,
        @CustomType.Parameter("captchaFooter") String captchaFooter,
        @CustomType.Parameter("captchaHeader") String captchaHeader,
        @CustomType.Parameter("captchaSubmitLabel") String captchaSubmitLabel,
        @CustomType.Parameter("captchaTitle") String captchaTitle) {
        this.blockAction = blockAction;
        this.blockErrorPageCode = blockErrorPageCode;
        this.blockErrorPageDescription = blockErrorPageDescription;
        this.blockErrorPageMessage = blockErrorPageMessage;
        this.blockResponseCode = blockResponseCode;
        this.captchaFooter = captchaFooter;
        this.captchaHeader = captchaHeader;
        this.captchaSubmitLabel = captchaSubmitLabel;
        this.captchaTitle = captchaTitle;
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

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetWaasPolicyWafConfigHumanInteractionChallengeChallengeSettings defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String blockAction;
        private String blockErrorPageCode;
        private String blockErrorPageDescription;
        private String blockErrorPageMessage;
        private Integer blockResponseCode;
        private String captchaFooter;
        private String captchaHeader;
        private String captchaSubmitLabel;
        private String captchaTitle;

        public Builder() {
    	      // Empty
        }

        public Builder(GetWaasPolicyWafConfigHumanInteractionChallengeChallengeSettings defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.blockAction = defaults.blockAction;
    	      this.blockErrorPageCode = defaults.blockErrorPageCode;
    	      this.blockErrorPageDescription = defaults.blockErrorPageDescription;
    	      this.blockErrorPageMessage = defaults.blockErrorPageMessage;
    	      this.blockResponseCode = defaults.blockResponseCode;
    	      this.captchaFooter = defaults.captchaFooter;
    	      this.captchaHeader = defaults.captchaHeader;
    	      this.captchaSubmitLabel = defaults.captchaSubmitLabel;
    	      this.captchaTitle = defaults.captchaTitle;
        }

        public Builder blockAction(String blockAction) {
            this.blockAction = Objects.requireNonNull(blockAction);
            return this;
        }
        public Builder blockErrorPageCode(String blockErrorPageCode) {
            this.blockErrorPageCode = Objects.requireNonNull(blockErrorPageCode);
            return this;
        }
        public Builder blockErrorPageDescription(String blockErrorPageDescription) {
            this.blockErrorPageDescription = Objects.requireNonNull(blockErrorPageDescription);
            return this;
        }
        public Builder blockErrorPageMessage(String blockErrorPageMessage) {
            this.blockErrorPageMessage = Objects.requireNonNull(blockErrorPageMessage);
            return this;
        }
        public Builder blockResponseCode(Integer blockResponseCode) {
            this.blockResponseCode = Objects.requireNonNull(blockResponseCode);
            return this;
        }
        public Builder captchaFooter(String captchaFooter) {
            this.captchaFooter = Objects.requireNonNull(captchaFooter);
            return this;
        }
        public Builder captchaHeader(String captchaHeader) {
            this.captchaHeader = Objects.requireNonNull(captchaHeader);
            return this;
        }
        public Builder captchaSubmitLabel(String captchaSubmitLabel) {
            this.captchaSubmitLabel = Objects.requireNonNull(captchaSubmitLabel);
            return this;
        }
        public Builder captchaTitle(String captchaTitle) {
            this.captchaTitle = Objects.requireNonNull(captchaTitle);
            return this;
        }        public GetWaasPolicyWafConfigHumanInteractionChallengeChallengeSettings build() {
            return new GetWaasPolicyWafConfigHumanInteractionChallengeChallengeSettings(blockAction, blockErrorPageCode, blockErrorPageDescription, blockErrorPageMessage, blockResponseCode, captchaFooter, captchaHeader, captchaSubmitLabel, captchaTitle);
        }
    }
}
