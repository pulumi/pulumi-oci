// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class GetLoadBalancersLoadBalancerShapeDetail {
    /**
     * @return Bandwidth in Mbps that determines the maximum bandwidth (ingress plus egress) that the load balancer can achieve. This bandwidth cannot be always guaranteed. For a guaranteed bandwidth use the minimumBandwidthInMbps parameter.
     * 
     */
    private Integer maximumBandwidthInMbps;
    /**
     * @return Bandwidth in Mbps that determines the total pre-provisioned bandwidth (ingress plus egress). The values must be between 0 and the maximumBandwidthInMbps in multiples of 10. The current allowed maximum value is defined in [Service Limits](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/servicelimits.htm).  Example: `150`
     * 
     */
    private Integer minimumBandwidthInMbps;

    private GetLoadBalancersLoadBalancerShapeDetail() {}
    /**
     * @return Bandwidth in Mbps that determines the maximum bandwidth (ingress plus egress) that the load balancer can achieve. This bandwidth cannot be always guaranteed. For a guaranteed bandwidth use the minimumBandwidthInMbps parameter.
     * 
     */
    public Integer maximumBandwidthInMbps() {
        return this.maximumBandwidthInMbps;
    }
    /**
     * @return Bandwidth in Mbps that determines the total pre-provisioned bandwidth (ingress plus egress). The values must be between 0 and the maximumBandwidthInMbps in multiples of 10. The current allowed maximum value is defined in [Service Limits](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/servicelimits.htm).  Example: `150`
     * 
     */
    public Integer minimumBandwidthInMbps() {
        return this.minimumBandwidthInMbps;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetLoadBalancersLoadBalancerShapeDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer maximumBandwidthInMbps;
        private Integer minimumBandwidthInMbps;
        public Builder() {}
        public Builder(GetLoadBalancersLoadBalancerShapeDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.maximumBandwidthInMbps = defaults.maximumBandwidthInMbps;
    	      this.minimumBandwidthInMbps = defaults.minimumBandwidthInMbps;
        }

        @CustomType.Setter
        public Builder maximumBandwidthInMbps(Integer maximumBandwidthInMbps) {
            this.maximumBandwidthInMbps = Objects.requireNonNull(maximumBandwidthInMbps);
            return this;
        }
        @CustomType.Setter
        public Builder minimumBandwidthInMbps(Integer minimumBandwidthInMbps) {
            this.minimumBandwidthInMbps = Objects.requireNonNull(minimumBandwidthInMbps);
            return this;
        }
        public GetLoadBalancersLoadBalancerShapeDetail build() {
            final var o = new GetLoadBalancersLoadBalancerShapeDetail();
            o.maximumBandwidthInMbps = maximumBandwidthInMbps;
            o.minimumBandwidthInMbps = minimumBandwidthInMbps;
            return o;
        }
    }
}