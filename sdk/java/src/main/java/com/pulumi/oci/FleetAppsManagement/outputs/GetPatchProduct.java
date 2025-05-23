// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetPatchProduct {
    /**
     * @return PlatformConfiguration Id corresponding to the Product
     * 
     */
    private String platformConfigurationId;
    /**
     * @return product version.
     * 
     */
    private String version;

    private GetPatchProduct() {}
    /**
     * @return PlatformConfiguration Id corresponding to the Product
     * 
     */
    public String platformConfigurationId() {
        return this.platformConfigurationId;
    }
    /**
     * @return product version.
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPatchProduct defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String platformConfigurationId;
        private String version;
        public Builder() {}
        public Builder(GetPatchProduct defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.platformConfigurationId = defaults.platformConfigurationId;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder platformConfigurationId(String platformConfigurationId) {
            if (platformConfigurationId == null) {
              throw new MissingRequiredPropertyException("GetPatchProduct", "platformConfigurationId");
            }
            this.platformConfigurationId = platformConfigurationId;
            return this;
        }
        @CustomType.Setter
        public Builder version(String version) {
            if (version == null) {
              throw new MissingRequiredPropertyException("GetPatchProduct", "version");
            }
            this.version = version;
            return this;
        }
        public GetPatchProduct build() {
            final var _resultValue = new GetPatchProduct();
            _resultValue.platformConfigurationId = platformConfigurationId;
            _resultValue.version = version;
            return _resultValue;
        }
    }
}
