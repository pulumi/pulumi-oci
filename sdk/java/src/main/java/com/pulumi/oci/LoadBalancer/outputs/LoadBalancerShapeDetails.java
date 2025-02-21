// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class LoadBalancerShapeDetails {
    /**
     * @return (Updatable) Bandwidth in Mbps that determines the maximum bandwidth (ingress plus egress) that the load balancer can achieve. This bandwidth cannot be always guaranteed. For a guaranteed bandwidth use the minimumBandwidthInMbps parameter.
     * 
     * The values must be between minimumBandwidthInMbps and 8000 (8Gbps).
     * 
     * Example: `1500`
     * 
     */
    private Integer maximumBandwidthInMbps;
    /**
     * @return (Updatable) Bandwidth in Mbps that determines the total pre-provisioned bandwidth (ingress plus egress). The values must be between 10 and the maximumBandwidthInMbps.  Example: `150`
     * 
     */
    private Integer minimumBandwidthInMbps;

    private LoadBalancerShapeDetails() {}
    /**
     * @return (Updatable) Bandwidth in Mbps that determines the maximum bandwidth (ingress plus egress) that the load balancer can achieve. This bandwidth cannot be always guaranteed. For a guaranteed bandwidth use the minimumBandwidthInMbps parameter.
     * 
     * The values must be between minimumBandwidthInMbps and 8000 (8Gbps).
     * 
     * Example: `1500`
     * 
     */
    public Integer maximumBandwidthInMbps() {
        return this.maximumBandwidthInMbps;
    }
    /**
     * @return (Updatable) Bandwidth in Mbps that determines the total pre-provisioned bandwidth (ingress plus egress). The values must be between 10 and the maximumBandwidthInMbps.  Example: `150`
     * 
     */
    public Integer minimumBandwidthInMbps() {
        return this.minimumBandwidthInMbps;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(LoadBalancerShapeDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer maximumBandwidthInMbps;
        private Integer minimumBandwidthInMbps;
        public Builder() {}
        public Builder(LoadBalancerShapeDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.maximumBandwidthInMbps = defaults.maximumBandwidthInMbps;
    	      this.minimumBandwidthInMbps = defaults.minimumBandwidthInMbps;
        }

        @CustomType.Setter
        public Builder maximumBandwidthInMbps(Integer maximumBandwidthInMbps) {
            if (maximumBandwidthInMbps == null) {
              throw new MissingRequiredPropertyException("LoadBalancerShapeDetails", "maximumBandwidthInMbps");
            }
            this.maximumBandwidthInMbps = maximumBandwidthInMbps;
            return this;
        }
        @CustomType.Setter
        public Builder minimumBandwidthInMbps(Integer minimumBandwidthInMbps) {
            if (minimumBandwidthInMbps == null) {
              throw new MissingRequiredPropertyException("LoadBalancerShapeDetails", "minimumBandwidthInMbps");
            }
            this.minimumBandwidthInMbps = minimumBandwidthInMbps;
            return this;
        }
        public LoadBalancerShapeDetails build() {
            final var _resultValue = new LoadBalancerShapeDetails();
            _resultValue.maximumBandwidthInMbps = maximumBandwidthInMbps;
            _resultValue.minimumBandwidthInMbps = minimumBandwidthInMbps;
            return _resultValue;
        }
    }
}
