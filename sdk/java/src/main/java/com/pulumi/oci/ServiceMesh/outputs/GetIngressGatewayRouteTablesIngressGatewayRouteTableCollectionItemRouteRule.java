// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ServiceMesh.outputs.GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRuleDestination;
import com.pulumi.oci.ServiceMesh.outputs.GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRuleIngressGatewayHost;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRule {
    /**
     * @return The destination of the request.
     * 
     */
    private List<GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRuleDestination> destinations;
    /**
     * @return The ingress gateway host to which the route rule attaches. If not specified, the route rule gets attached to all hosts on the ingress gateway.
     * 
     */
    private List<GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRuleIngressGatewayHost> ingressGatewayHosts;
    /**
     * @return If true, the rule will check that the content-type header has a application/grpc or one of the various application/grpc+ values.
     * 
     */
    private Boolean isGrpc;
    /**
     * @return If true, the hostname will be rewritten to the target virtual deployment&#39;s DNS hostname.
     * 
     */
    private Boolean isHostRewriteEnabled;
    /**
     * @return If true, the matched path prefix will be rewritten to &#39;/&#39; before being directed to the target virtual deployment.
     * 
     */
    private Boolean isPathRewriteEnabled;
    /**
     * @return Route to match
     * 
     */
    private String path;
    /**
     * @return Match type for the route
     * 
     */
    private String pathType;
    /**
     * @return The maximum duration in milliseconds for the upstream service to respond to a request.  If provided, the timeout value overrides the default timeout of 15 seconds for the HTTP based route rules, and disabled (no timeout) when &#39;isGrpc&#39; is true.  The value 0 (zero) indicates that the timeout is disabled.  For streaming responses from the upstream service, consider either keeping the timeout disabled or set a sufficiently high value.
     * 
     */
    private String requestTimeoutInMs;
    /**
     * @return Type of protocol.
     * 
     */
    private String type;

    private GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRule() {}
    /**
     * @return The destination of the request.
     * 
     */
    public List<GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRuleDestination> destinations() {
        return this.destinations;
    }
    /**
     * @return The ingress gateway host to which the route rule attaches. If not specified, the route rule gets attached to all hosts on the ingress gateway.
     * 
     */
    public List<GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRuleIngressGatewayHost> ingressGatewayHosts() {
        return this.ingressGatewayHosts;
    }
    /**
     * @return If true, the rule will check that the content-type header has a application/grpc or one of the various application/grpc+ values.
     * 
     */
    public Boolean isGrpc() {
        return this.isGrpc;
    }
    /**
     * @return If true, the hostname will be rewritten to the target virtual deployment&#39;s DNS hostname.
     * 
     */
    public Boolean isHostRewriteEnabled() {
        return this.isHostRewriteEnabled;
    }
    /**
     * @return If true, the matched path prefix will be rewritten to &#39;/&#39; before being directed to the target virtual deployment.
     * 
     */
    public Boolean isPathRewriteEnabled() {
        return this.isPathRewriteEnabled;
    }
    /**
     * @return Route to match
     * 
     */
    public String path() {
        return this.path;
    }
    /**
     * @return Match type for the route
     * 
     */
    public String pathType() {
        return this.pathType;
    }
    /**
     * @return The maximum duration in milliseconds for the upstream service to respond to a request.  If provided, the timeout value overrides the default timeout of 15 seconds for the HTTP based route rules, and disabled (no timeout) when &#39;isGrpc&#39; is true.  The value 0 (zero) indicates that the timeout is disabled.  For streaming responses from the upstream service, consider either keeping the timeout disabled or set a sufficiently high value.
     * 
     */
    public String requestTimeoutInMs() {
        return this.requestTimeoutInMs;
    }
    /**
     * @return Type of protocol.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRuleDestination> destinations;
        private List<GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRuleIngressGatewayHost> ingressGatewayHosts;
        private Boolean isGrpc;
        private Boolean isHostRewriteEnabled;
        private Boolean isPathRewriteEnabled;
        private String path;
        private String pathType;
        private String requestTimeoutInMs;
        private String type;
        public Builder() {}
        public Builder(GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.destinations = defaults.destinations;
    	      this.ingressGatewayHosts = defaults.ingressGatewayHosts;
    	      this.isGrpc = defaults.isGrpc;
    	      this.isHostRewriteEnabled = defaults.isHostRewriteEnabled;
    	      this.isPathRewriteEnabled = defaults.isPathRewriteEnabled;
    	      this.path = defaults.path;
    	      this.pathType = defaults.pathType;
    	      this.requestTimeoutInMs = defaults.requestTimeoutInMs;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder destinations(List<GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRuleDestination> destinations) {
            if (destinations == null) {
              throw new MissingRequiredPropertyException("GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRule", "destinations");
            }
            this.destinations = destinations;
            return this;
        }
        public Builder destinations(GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRuleDestination... destinations) {
            return destinations(List.of(destinations));
        }
        @CustomType.Setter
        public Builder ingressGatewayHosts(List<GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRuleIngressGatewayHost> ingressGatewayHosts) {
            if (ingressGatewayHosts == null) {
              throw new MissingRequiredPropertyException("GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRule", "ingressGatewayHosts");
            }
            this.ingressGatewayHosts = ingressGatewayHosts;
            return this;
        }
        public Builder ingressGatewayHosts(GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRuleIngressGatewayHost... ingressGatewayHosts) {
            return ingressGatewayHosts(List.of(ingressGatewayHosts));
        }
        @CustomType.Setter
        public Builder isGrpc(Boolean isGrpc) {
            if (isGrpc == null) {
              throw new MissingRequiredPropertyException("GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRule", "isGrpc");
            }
            this.isGrpc = isGrpc;
            return this;
        }
        @CustomType.Setter
        public Builder isHostRewriteEnabled(Boolean isHostRewriteEnabled) {
            if (isHostRewriteEnabled == null) {
              throw new MissingRequiredPropertyException("GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRule", "isHostRewriteEnabled");
            }
            this.isHostRewriteEnabled = isHostRewriteEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder isPathRewriteEnabled(Boolean isPathRewriteEnabled) {
            if (isPathRewriteEnabled == null) {
              throw new MissingRequiredPropertyException("GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRule", "isPathRewriteEnabled");
            }
            this.isPathRewriteEnabled = isPathRewriteEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder path(String path) {
            if (path == null) {
              throw new MissingRequiredPropertyException("GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRule", "path");
            }
            this.path = path;
            return this;
        }
        @CustomType.Setter
        public Builder pathType(String pathType) {
            if (pathType == null) {
              throw new MissingRequiredPropertyException("GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRule", "pathType");
            }
            this.pathType = pathType;
            return this;
        }
        @CustomType.Setter
        public Builder requestTimeoutInMs(String requestTimeoutInMs) {
            if (requestTimeoutInMs == null) {
              throw new MissingRequiredPropertyException("GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRule", "requestTimeoutInMs");
            }
            this.requestTimeoutInMs = requestTimeoutInMs;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRule", "type");
            }
            this.type = type;
            return this;
        }
        public GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRule build() {
            final var _resultValue = new GetIngressGatewayRouteTablesIngressGatewayRouteTableCollectionItemRouteRule();
            _resultValue.destinations = destinations;
            _resultValue.ingressGatewayHosts = ingressGatewayHosts;
            _resultValue.isGrpc = isGrpc;
            _resultValue.isHostRewriteEnabled = isHostRewriteEnabled;
            _resultValue.isPathRewriteEnabled = isPathRewriteEnabled;
            _resultValue.path = path;
            _resultValue.pathType = pathType;
            _resultValue.requestTimeoutInMs = requestTimeoutInMs;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
