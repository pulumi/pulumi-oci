// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Analytics.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcn {
    /**
     * @return The Virtual Cloud Network OCID.
     * 
     */
    private @Nullable String id;
    /**
     * @return Source IP addresses or IP address ranges in ingress rules.
     * 
     */
    private @Nullable List<String> whitelistedIps;

    private AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcn() {}
    /**
     * @return The Virtual Cloud Network OCID.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return Source IP addresses or IP address ranges in ingress rules.
     * 
     */
    public List<String> whitelistedIps() {
        return this.whitelistedIps == null ? List.of() : this.whitelistedIps;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcn defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String id;
        private @Nullable List<String> whitelistedIps;
        public Builder() {}
        public Builder(AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcn defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.whitelistedIps = defaults.whitelistedIps;
        }

        @CustomType.Setter
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder whitelistedIps(@Nullable List<String> whitelistedIps) {
            this.whitelistedIps = whitelistedIps;
            return this;
        }
        public Builder whitelistedIps(String... whitelistedIps) {
            return whitelistedIps(List.of(whitelistedIps));
        }
        public AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcn build() {
            final var o = new AnalyticsInstanceNetworkEndpointDetailsWhitelistedVcn();
            o.id = id;
            o.whitelistedIps = whitelistedIps;
            return o;
        }
    }
}