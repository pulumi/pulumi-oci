// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetVirtualCircuitBandwidthShapesVirtualCircuitBandwidthShape {
    /**
     * @return The bandwidth in Mbps.  Example: `10000`
     * 
     */
    private final Integer bandwidthInMbps;
    /**
     * @return The name of the bandwidth shape.  Example: `10 Gbps`
     * 
     */
    private final String name;

    @CustomType.Constructor
    private GetVirtualCircuitBandwidthShapesVirtualCircuitBandwidthShape(
        @CustomType.Parameter("bandwidthInMbps") Integer bandwidthInMbps,
        @CustomType.Parameter("name") String name) {
        this.bandwidthInMbps = bandwidthInMbps;
        this.name = name;
    }

    /**
     * @return The bandwidth in Mbps.  Example: `10000`
     * 
     */
    public Integer bandwidthInMbps() {
        return this.bandwidthInMbps;
    }
    /**
     * @return The name of the bandwidth shape.  Example: `10 Gbps`
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVirtualCircuitBandwidthShapesVirtualCircuitBandwidthShape defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Integer bandwidthInMbps;
        private String name;

        public Builder() {
    	      // Empty
        }

        public Builder(GetVirtualCircuitBandwidthShapesVirtualCircuitBandwidthShape defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.bandwidthInMbps = defaults.bandwidthInMbps;
    	      this.name = defaults.name;
        }

        public Builder bandwidthInMbps(Integer bandwidthInMbps) {
            this.bandwidthInMbps = Objects.requireNonNull(bandwidthInMbps);
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }        public GetVirtualCircuitBandwidthShapesVirtualCircuitBandwidthShape build() {
            return new GetVirtualCircuitBandwidthShapesVirtualCircuitBandwidthShape(bandwidthInMbps, name);
        }
    }
}
