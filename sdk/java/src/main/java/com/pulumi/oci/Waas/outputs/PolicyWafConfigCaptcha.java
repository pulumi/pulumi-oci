// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class PolicyWafConfigCaptcha {
    /**
     * @return (Updatable) The text to show when incorrect CAPTCHA text is entered. If unspecified, defaults to `The CAPTCHA was incorrect. Try again.`
     * 
     */
    private String failureMessage;
    /**
     * @return (Updatable) The text to show in the footer when showing a CAPTCHA challenge. If unspecified, defaults to &#39;Enter the letters and numbers as they are shown in the image above.&#39;
     * 
     */
    private @Nullable String footerText;
    /**
     * @return (Updatable) The text to show in the header when showing a CAPTCHA challenge. If unspecified, defaults to &#39;We have detected an increased number of attempts to access this website. To help us keep this site secure, please let us know that you are not a robot by entering the text from the image below.&#39;
     * 
     */
    private @Nullable String headerText;
    /**
     * @return (Updatable) The amount of time before the CAPTCHA expires, in seconds. If unspecified, defaults to `300`.
     * 
     */
    private Integer sessionExpirationInSeconds;
    /**
     * @return (Updatable) The text to show on the label of the CAPTCHA challenge submit button. If unspecified, defaults to `Yes, I am human`.
     * 
     */
    private String submitLabel;
    /**
     * @return (Updatable) The title used when displaying a CAPTCHA challenge. If unspecified, defaults to `Are you human?`
     * 
     */
    private String title;
    /**
     * @return (Updatable) The unique URL path at which to show the CAPTCHA challenge.
     * 
     */
    private String url;

    private PolicyWafConfigCaptcha() {}
    /**
     * @return (Updatable) The text to show when incorrect CAPTCHA text is entered. If unspecified, defaults to `The CAPTCHA was incorrect. Try again.`
     * 
     */
    public String failureMessage() {
        return this.failureMessage;
    }
    /**
     * @return (Updatable) The text to show in the footer when showing a CAPTCHA challenge. If unspecified, defaults to &#39;Enter the letters and numbers as they are shown in the image above.&#39;
     * 
     */
    public Optional<String> footerText() {
        return Optional.ofNullable(this.footerText);
    }
    /**
     * @return (Updatable) The text to show in the header when showing a CAPTCHA challenge. If unspecified, defaults to &#39;We have detected an increased number of attempts to access this website. To help us keep this site secure, please let us know that you are not a robot by entering the text from the image below.&#39;
     * 
     */
    public Optional<String> headerText() {
        return Optional.ofNullable(this.headerText);
    }
    /**
     * @return (Updatable) The amount of time before the CAPTCHA expires, in seconds. If unspecified, defaults to `300`.
     * 
     */
    public Integer sessionExpirationInSeconds() {
        return this.sessionExpirationInSeconds;
    }
    /**
     * @return (Updatable) The text to show on the label of the CAPTCHA challenge submit button. If unspecified, defaults to `Yes, I am human`.
     * 
     */
    public String submitLabel() {
        return this.submitLabel;
    }
    /**
     * @return (Updatable) The title used when displaying a CAPTCHA challenge. If unspecified, defaults to `Are you human?`
     * 
     */
    public String title() {
        return this.title;
    }
    /**
     * @return (Updatable) The unique URL path at which to show the CAPTCHA challenge.
     * 
     */
    public String url() {
        return this.url;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(PolicyWafConfigCaptcha defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String failureMessage;
        private @Nullable String footerText;
        private @Nullable String headerText;
        private Integer sessionExpirationInSeconds;
        private String submitLabel;
        private String title;
        private String url;
        public Builder() {}
        public Builder(PolicyWafConfigCaptcha defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.failureMessage = defaults.failureMessage;
    	      this.footerText = defaults.footerText;
    	      this.headerText = defaults.headerText;
    	      this.sessionExpirationInSeconds = defaults.sessionExpirationInSeconds;
    	      this.submitLabel = defaults.submitLabel;
    	      this.title = defaults.title;
    	      this.url = defaults.url;
        }

        @CustomType.Setter
        public Builder failureMessage(String failureMessage) {
            if (failureMessage == null) {
              throw new MissingRequiredPropertyException("PolicyWafConfigCaptcha", "failureMessage");
            }
            this.failureMessage = failureMessage;
            return this;
        }
        @CustomType.Setter
        public Builder footerText(@Nullable String footerText) {

            this.footerText = footerText;
            return this;
        }
        @CustomType.Setter
        public Builder headerText(@Nullable String headerText) {

            this.headerText = headerText;
            return this;
        }
        @CustomType.Setter
        public Builder sessionExpirationInSeconds(Integer sessionExpirationInSeconds) {
            if (sessionExpirationInSeconds == null) {
              throw new MissingRequiredPropertyException("PolicyWafConfigCaptcha", "sessionExpirationInSeconds");
            }
            this.sessionExpirationInSeconds = sessionExpirationInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder submitLabel(String submitLabel) {
            if (submitLabel == null) {
              throw new MissingRequiredPropertyException("PolicyWafConfigCaptcha", "submitLabel");
            }
            this.submitLabel = submitLabel;
            return this;
        }
        @CustomType.Setter
        public Builder title(String title) {
            if (title == null) {
              throw new MissingRequiredPropertyException("PolicyWafConfigCaptcha", "title");
            }
            this.title = title;
            return this;
        }
        @CustomType.Setter
        public Builder url(String url) {
            if (url == null) {
              throw new MissingRequiredPropertyException("PolicyWafConfigCaptcha", "url");
            }
            this.url = url;
            return this;
        }
        public PolicyWafConfigCaptcha build() {
            final var _resultValue = new PolicyWafConfigCaptcha();
            _resultValue.failureMessage = failureMessage;
            _resultValue.footerText = footerText;
            _resultValue.headerText = headerText;
            _resultValue.sessionExpirationInSeconds = sessionExpirationInSeconds;
            _resultValue.submitLabel = submitLabel;
            _resultValue.title = title;
            _resultValue.url = url;
            return _resultValue;
        }
    }
}
