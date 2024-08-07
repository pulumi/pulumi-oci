// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsCloudGateMappingsCloudGateMappingUpstreamServerGroup {
    /**
     * @return The URI to the upstream block entry
     * 
     */
    private String ref;
    /**
     * @return SSL flag for the Upstream Block
     * 
     */
    private Boolean ssl;
    /**
     * @return The id of the upstream block entry.
     * 
     */
    private String value;

    private GetDomainsCloudGateMappingsCloudGateMappingUpstreamServerGroup() {}
    /**
     * @return The URI to the upstream block entry
     * 
     */
    public String ref() {
        return this.ref;
    }
    /**
     * @return SSL flag for the Upstream Block
     * 
     */
    public Boolean ssl() {
        return this.ssl;
    }
    /**
     * @return The id of the upstream block entry.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsCloudGateMappingsCloudGateMappingUpstreamServerGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String ref;
        private Boolean ssl;
        private String value;
        public Builder() {}
        public Builder(GetDomainsCloudGateMappingsCloudGateMappingUpstreamServerGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ref = defaults.ref;
    	      this.ssl = defaults.ssl;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder ref(String ref) {
            if (ref == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateMappingsCloudGateMappingUpstreamServerGroup", "ref");
            }
            this.ref = ref;
            return this;
        }
        @CustomType.Setter
        public Builder ssl(Boolean ssl) {
            if (ssl == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateMappingsCloudGateMappingUpstreamServerGroup", "ssl");
            }
            this.ssl = ssl;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetDomainsCloudGateMappingsCloudGateMappingUpstreamServerGroup", "value");
            }
            this.value = value;
            return this;
        }
        public GetDomainsCloudGateMappingsCloudGateMappingUpstreamServerGroup build() {
            final var _resultValue = new GetDomainsCloudGateMappingsCloudGateMappingUpstreamServerGroup();
            _resultValue.ref = ref;
            _resultValue.ssl = ssl;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
