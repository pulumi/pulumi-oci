// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.util.Objects;

@CustomType
public final class GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingThirdPartyFactor {
    /**
     * @return To enable Duo Security factor
     * 
     */
    private Boolean duoSecurity;

    private GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingThirdPartyFactor() {}
    /**
     * @return To enable Duo Security factor
     * 
     */
    public Boolean duoSecurity() {
        return this.duoSecurity;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingThirdPartyFactor defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean duoSecurity;
        public Builder() {}
        public Builder(GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingThirdPartyFactor defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.duoSecurity = defaults.duoSecurity;
        }

        @CustomType.Setter
        public Builder duoSecurity(Boolean duoSecurity) {
            this.duoSecurity = Objects.requireNonNull(duoSecurity);
            return this;
        }
        public GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingThirdPartyFactor build() {
            final var o = new GetDomainsAuthenticationFactorSettingsAuthenticationFactorSettingThirdPartyFactor();
            o.duoSecurity = duoSecurity;
            return o;
        }
    }
}