// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ServiceMesh.outputs.VirtualServiceRouteTableRouteRuleDestination;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class VirtualServiceRouteTableRouteRule {
    /**
     * @return (Updatable) The destination of the request.
     * 
     */
    private List<VirtualServiceRouteTableRouteRuleDestination> destinations;
    /**
     * @return (Updatable) If true, the rule will check that the content-type header has a application/grpc or one of the various application/grpc+ values.
     * 
     */
    private @Nullable Boolean isGrpc;
    /**
     * @return (Updatable) Route to match
     * 
     */
    private @Nullable String path;
    /**
     * @return (Updatable) Match type for the route
     * 
     */
    private @Nullable String pathType;
    /**
     * @return (Updatable) The maximum duration in milliseconds for the target service to respond to a request.  If provided, the timeout value overrides the default timeout of 15 seconds for the HTTP based route rules, and disabled (no timeout) when &#39;isGrpc&#39; is true.  The value 0 (zero) indicates that the timeout is disabled.  For streaming responses from the target service, consider either keeping the timeout disabled or set a sufficiently high value.
     * 
     */
    private @Nullable String requestTimeoutInMs;
    /**
     * @return (Updatable) Type of protocol.
     * 
     */
    private String type;

    private VirtualServiceRouteTableRouteRule() {}
    /**
     * @return (Updatable) The destination of the request.
     * 
     */
    public List<VirtualServiceRouteTableRouteRuleDestination> destinations() {
        return this.destinations;
    }
    /**
     * @return (Updatable) If true, the rule will check that the content-type header has a application/grpc or one of the various application/grpc+ values.
     * 
     */
    public Optional<Boolean> isGrpc() {
        return Optional.ofNullable(this.isGrpc);
    }
    /**
     * @return (Updatable) Route to match
     * 
     */
    public Optional<String> path() {
        return Optional.ofNullable(this.path);
    }
    /**
     * @return (Updatable) Match type for the route
     * 
     */
    public Optional<String> pathType() {
        return Optional.ofNullable(this.pathType);
    }
    /**
     * @return (Updatable) The maximum duration in milliseconds for the target service to respond to a request.  If provided, the timeout value overrides the default timeout of 15 seconds for the HTTP based route rules, and disabled (no timeout) when &#39;isGrpc&#39; is true.  The value 0 (zero) indicates that the timeout is disabled.  For streaming responses from the target service, consider either keeping the timeout disabled or set a sufficiently high value.
     * 
     */
    public Optional<String> requestTimeoutInMs() {
        return Optional.ofNullable(this.requestTimeoutInMs);
    }
    /**
     * @return (Updatable) Type of protocol.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(VirtualServiceRouteTableRouteRule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<VirtualServiceRouteTableRouteRuleDestination> destinations;
        private @Nullable Boolean isGrpc;
        private @Nullable String path;
        private @Nullable String pathType;
        private @Nullable String requestTimeoutInMs;
        private String type;
        public Builder() {}
        public Builder(VirtualServiceRouteTableRouteRule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.destinations = defaults.destinations;
    	      this.isGrpc = defaults.isGrpc;
    	      this.path = defaults.path;
    	      this.pathType = defaults.pathType;
    	      this.requestTimeoutInMs = defaults.requestTimeoutInMs;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder destinations(List<VirtualServiceRouteTableRouteRuleDestination> destinations) {
            if (destinations == null) {
              throw new MissingRequiredPropertyException("VirtualServiceRouteTableRouteRule", "destinations");
            }
            this.destinations = destinations;
            return this;
        }
        public Builder destinations(VirtualServiceRouteTableRouteRuleDestination... destinations) {
            return destinations(List.of(destinations));
        }
        @CustomType.Setter
        public Builder isGrpc(@Nullable Boolean isGrpc) {

            this.isGrpc = isGrpc;
            return this;
        }
        @CustomType.Setter
        public Builder path(@Nullable String path) {

            this.path = path;
            return this;
        }
        @CustomType.Setter
        public Builder pathType(@Nullable String pathType) {

            this.pathType = pathType;
            return this;
        }
        @CustomType.Setter
        public Builder requestTimeoutInMs(@Nullable String requestTimeoutInMs) {

            this.requestTimeoutInMs = requestTimeoutInMs;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("VirtualServiceRouteTableRouteRule", "type");
            }
            this.type = type;
            return this;
        }
        public VirtualServiceRouteTableRouteRule build() {
            final var _resultValue = new VirtualServiceRouteTableRouteRule();
            _resultValue.destinations = destinations;
            _resultValue.isGrpc = isGrpc;
            _resultValue.path = path;
            _resultValue.pathType = pathType;
            _resultValue.requestTimeoutInMs = requestTimeoutInMs;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
