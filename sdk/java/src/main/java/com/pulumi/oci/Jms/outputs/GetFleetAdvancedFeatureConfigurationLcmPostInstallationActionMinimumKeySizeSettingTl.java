// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingTl {
    /**
     * @return Key size for the encryption algorithm. Allowed values: 256 for EC, 2048 for DH/DSA/RSA
     * 
     */
    private Integer keySize;
    /**
     * @return The algorithm name.
     * 
     */
    private String name;

    private GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingTl() {}
    /**
     * @return Key size for the encryption algorithm. Allowed values: 256 for EC, 2048 for DH/DSA/RSA
     * 
     */
    public Integer keySize() {
        return this.keySize;
    }
    /**
     * @return The algorithm name.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingTl defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer keySize;
        private String name;
        public Builder() {}
        public Builder(GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingTl defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.keySize = defaults.keySize;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder keySize(Integer keySize) {
            this.keySize = Objects.requireNonNull(keySize);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingTl build() {
            final var o = new GetFleetAdvancedFeatureConfigurationLcmPostInstallationActionMinimumKeySizeSettingTl();
            o.keySize = keySize;
            o.name = name;
            return o;
        }
    }
}