// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingEmailSetting {
    /**
     * @return Custom redirect Url which will be used in email link
     * 
     */
    private String emailLinkCustomUrl;
    /**
     * @return Specifies whether Email link is enabled or not.
     * 
     */
    private Boolean emailLinkEnabled;

    private GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingEmailSetting() {}
    /**
     * @return Custom redirect Url which will be used in email link
     * 
     */
    public String emailLinkCustomUrl() {
        return this.emailLinkCustomUrl;
    }
    /**
     * @return Specifies whether Email link is enabled or not.
     * 
     */
    public Boolean emailLinkEnabled() {
        return this.emailLinkEnabled;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingEmailSetting defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String emailLinkCustomUrl;
        private Boolean emailLinkEnabled;
        public Builder() {}
        public Builder(GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingEmailSetting defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.emailLinkCustomUrl = defaults.emailLinkCustomUrl;
    	      this.emailLinkEnabled = defaults.emailLinkEnabled;
        }

        @CustomType.Setter
        public Builder emailLinkCustomUrl(String emailLinkCustomUrl) {
            this.emailLinkCustomUrl = Objects.requireNonNull(emailLinkCustomUrl);
            return this;
        }
        @CustomType.Setter
        public Builder emailLinkEnabled(Boolean emailLinkEnabled) {
            this.emailLinkEnabled = Objects.requireNonNull(emailLinkEnabled);
            return this;
        }
        public GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingEmailSetting build() {
            final var o = new GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingEmailSetting();
            o.emailLinkCustomUrl = emailLinkCustomUrl;
            o.emailLinkEnabled = emailLinkEnabled;
            return o;
        }
    }
}