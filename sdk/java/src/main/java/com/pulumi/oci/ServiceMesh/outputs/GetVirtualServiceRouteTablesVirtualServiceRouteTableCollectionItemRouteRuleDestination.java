// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetVirtualServiceRouteTablesVirtualServiceRouteTableCollectionItemRouteRuleDestination {
    /**
     * @return Port on virtual deployment to target. If port is missing, the rule will target all ports on the virtual deployment.
     * 
     */
    private Integer port;
    /**
     * @return The OCID of the virtual deployment where the request will be routed.
     * 
     */
    private String virtualDeploymentId;
    /**
     * @return Weight of traffic target.
     * 
     */
    private Integer weight;

    private GetVirtualServiceRouteTablesVirtualServiceRouteTableCollectionItemRouteRuleDestination() {}
    /**
     * @return Port on virtual deployment to target. If port is missing, the rule will target all ports on the virtual deployment.
     * 
     */
    public Integer port() {
        return this.port;
    }
    /**
     * @return The OCID of the virtual deployment where the request will be routed.
     * 
     */
    public String virtualDeploymentId() {
        return this.virtualDeploymentId;
    }
    /**
     * @return Weight of traffic target.
     * 
     */
    public Integer weight() {
        return this.weight;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVirtualServiceRouteTablesVirtualServiceRouteTableCollectionItemRouteRuleDestination defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer port;
        private String virtualDeploymentId;
        private Integer weight;
        public Builder() {}
        public Builder(GetVirtualServiceRouteTablesVirtualServiceRouteTableCollectionItemRouteRuleDestination defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.port = defaults.port;
    	      this.virtualDeploymentId = defaults.virtualDeploymentId;
    	      this.weight = defaults.weight;
        }

        @CustomType.Setter
        public Builder port(Integer port) {
            this.port = Objects.requireNonNull(port);
            return this;
        }
        @CustomType.Setter
        public Builder virtualDeploymentId(String virtualDeploymentId) {
            this.virtualDeploymentId = Objects.requireNonNull(virtualDeploymentId);
            return this;
        }
        @CustomType.Setter
        public Builder weight(Integer weight) {
            this.weight = Objects.requireNonNull(weight);
            return this;
        }
        public GetVirtualServiceRouteTablesVirtualServiceRouteTableCollectionItemRouteRuleDestination build() {
            final var o = new GetVirtualServiceRouteTablesVirtualServiceRouteTableCollectionItemRouteRuleDestination();
            o.port = port;
            o.virtualDeploymentId = virtualDeploymentId;
            o.weight = weight;
            return o;
        }
    }
}