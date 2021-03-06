// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Integration.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcn {
    /**
     * @return Source IP addresses or IP address ranges ingress rules.
     * 
     */
    private final @Nullable List<String> allowlistedIps;
    /**
     * @return The Virtual Cloud Network OCID.
     * 
     */
    private final String id;

    @CustomType.Constructor
    private IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcn(
        @CustomType.Parameter("allowlistedIps") @Nullable List<String> allowlistedIps,
        @CustomType.Parameter("id") String id) {
        this.allowlistedIps = allowlistedIps;
        this.id = id;
    }

    /**
     * @return Source IP addresses or IP address ranges ingress rules.
     * 
     */
    public List<String> allowlistedIps() {
        return this.allowlistedIps == null ? List.of() : this.allowlistedIps;
    }
    /**
     * @return The Virtual Cloud Network OCID.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcn defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable List<String> allowlistedIps;
        private String id;

        public Builder() {
    	      // Empty
        }

        public Builder(IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcn defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allowlistedIps = defaults.allowlistedIps;
    	      this.id = defaults.id;
        }

        public Builder allowlistedIps(@Nullable List<String> allowlistedIps) {
            this.allowlistedIps = allowlistedIps;
            return this;
        }
        public Builder allowlistedIps(String... allowlistedIps) {
            return allowlistedIps(List.of(allowlistedIps));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }        public IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcn build() {
            return new IntegrationInstanceNetworkEndpointDetailsAllowlistedHttpVcn(allowlistedIps, id);
        }
    }
}
