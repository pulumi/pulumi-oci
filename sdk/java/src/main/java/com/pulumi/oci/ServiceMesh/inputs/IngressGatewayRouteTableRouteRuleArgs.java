// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ServiceMesh.inputs.IngressGatewayRouteTableRouteRuleDestinationArgs;
import com.pulumi.oci.ServiceMesh.inputs.IngressGatewayRouteTableRouteRuleIngressGatewayHostArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class IngressGatewayRouteTableRouteRuleArgs extends com.pulumi.resources.ResourceArgs {

    public static final IngressGatewayRouteTableRouteRuleArgs Empty = new IngressGatewayRouteTableRouteRuleArgs();

    /**
     * (Updatable) The destination of the request.
     * 
     */
    @Import(name="destinations", required=true)
    private Output<List<IngressGatewayRouteTableRouteRuleDestinationArgs>> destinations;

    /**
     * @return (Updatable) The destination of the request.
     * 
     */
    public Output<List<IngressGatewayRouteTableRouteRuleDestinationArgs>> destinations() {
        return this.destinations;
    }

    /**
     * (Updatable) The ingress gateway host to which the route rule attaches. If not specified, the route rule gets attached to all hosts on the ingress gateway.
     * 
     */
    @Import(name="ingressGatewayHost")
    private @Nullable Output<IngressGatewayRouteTableRouteRuleIngressGatewayHostArgs> ingressGatewayHost;

    /**
     * @return (Updatable) The ingress gateway host to which the route rule attaches. If not specified, the route rule gets attached to all hosts on the ingress gateway.
     * 
     */
    public Optional<Output<IngressGatewayRouteTableRouteRuleIngressGatewayHostArgs>> ingressGatewayHost() {
        return Optional.ofNullable(this.ingressGatewayHost);
    }

    /**
     * (Updatable) If true, the rule will check that the content-type header has a application/grpc or one of the various application/grpc+ values.
     * 
     */
    @Import(name="isGrpc")
    private @Nullable Output<Boolean> isGrpc;

    /**
     * @return (Updatable) If true, the rule will check that the content-type header has a application/grpc or one of the various application/grpc+ values.
     * 
     */
    public Optional<Output<Boolean>> isGrpc() {
        return Optional.ofNullable(this.isGrpc);
    }

    /**
     * (Updatable) If true, the hostname will be rewritten to the target virtual deployment&#39;s DNS hostname.
     * 
     */
    @Import(name="isHostRewriteEnabled")
    private @Nullable Output<Boolean> isHostRewriteEnabled;

    /**
     * @return (Updatable) If true, the hostname will be rewritten to the target virtual deployment&#39;s DNS hostname.
     * 
     */
    public Optional<Output<Boolean>> isHostRewriteEnabled() {
        return Optional.ofNullable(this.isHostRewriteEnabled);
    }

    /**
     * (Updatable) If true, the matched path prefix will be rewritten to &#39;/&#39; before being directed to the target virtual deployment.
     * 
     */
    @Import(name="isPathRewriteEnabled")
    private @Nullable Output<Boolean> isPathRewriteEnabled;

    /**
     * @return (Updatable) If true, the matched path prefix will be rewritten to &#39;/&#39; before being directed to the target virtual deployment.
     * 
     */
    public Optional<Output<Boolean>> isPathRewriteEnabled() {
        return Optional.ofNullable(this.isPathRewriteEnabled);
    }

    /**
     * (Updatable) Route to match
     * 
     */
    @Import(name="path")
    private @Nullable Output<String> path;

    /**
     * @return (Updatable) Route to match
     * 
     */
    public Optional<Output<String>> path() {
        return Optional.ofNullable(this.path);
    }

    /**
     * (Updatable) Match type for the route
     * 
     */
    @Import(name="pathType")
    private @Nullable Output<String> pathType;

    /**
     * @return (Updatable) Match type for the route
     * 
     */
    public Optional<Output<String>> pathType() {
        return Optional.ofNullable(this.pathType);
    }

    /**
     * (Updatable) Type of protocol.
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return (Updatable) Type of protocol.
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    private IngressGatewayRouteTableRouteRuleArgs() {}

    private IngressGatewayRouteTableRouteRuleArgs(IngressGatewayRouteTableRouteRuleArgs $) {
        this.destinations = $.destinations;
        this.ingressGatewayHost = $.ingressGatewayHost;
        this.isGrpc = $.isGrpc;
        this.isHostRewriteEnabled = $.isHostRewriteEnabled;
        this.isPathRewriteEnabled = $.isPathRewriteEnabled;
        this.path = $.path;
        this.pathType = $.pathType;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(IngressGatewayRouteTableRouteRuleArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private IngressGatewayRouteTableRouteRuleArgs $;

        public Builder() {
            $ = new IngressGatewayRouteTableRouteRuleArgs();
        }

        public Builder(IngressGatewayRouteTableRouteRuleArgs defaults) {
            $ = new IngressGatewayRouteTableRouteRuleArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param destinations (Updatable) The destination of the request.
         * 
         * @return builder
         * 
         */
        public Builder destinations(Output<List<IngressGatewayRouteTableRouteRuleDestinationArgs>> destinations) {
            $.destinations = destinations;
            return this;
        }

        /**
         * @param destinations (Updatable) The destination of the request.
         * 
         * @return builder
         * 
         */
        public Builder destinations(List<IngressGatewayRouteTableRouteRuleDestinationArgs> destinations) {
            return destinations(Output.of(destinations));
        }

        /**
         * @param destinations (Updatable) The destination of the request.
         * 
         * @return builder
         * 
         */
        public Builder destinations(IngressGatewayRouteTableRouteRuleDestinationArgs... destinations) {
            return destinations(List.of(destinations));
        }

        /**
         * @param ingressGatewayHost (Updatable) The ingress gateway host to which the route rule attaches. If not specified, the route rule gets attached to all hosts on the ingress gateway.
         * 
         * @return builder
         * 
         */
        public Builder ingressGatewayHost(@Nullable Output<IngressGatewayRouteTableRouteRuleIngressGatewayHostArgs> ingressGatewayHost) {
            $.ingressGatewayHost = ingressGatewayHost;
            return this;
        }

        /**
         * @param ingressGatewayHost (Updatable) The ingress gateway host to which the route rule attaches. If not specified, the route rule gets attached to all hosts on the ingress gateway.
         * 
         * @return builder
         * 
         */
        public Builder ingressGatewayHost(IngressGatewayRouteTableRouteRuleIngressGatewayHostArgs ingressGatewayHost) {
            return ingressGatewayHost(Output.of(ingressGatewayHost));
        }

        /**
         * @param isGrpc (Updatable) If true, the rule will check that the content-type header has a application/grpc or one of the various application/grpc+ values.
         * 
         * @return builder
         * 
         */
        public Builder isGrpc(@Nullable Output<Boolean> isGrpc) {
            $.isGrpc = isGrpc;
            return this;
        }

        /**
         * @param isGrpc (Updatable) If true, the rule will check that the content-type header has a application/grpc or one of the various application/grpc+ values.
         * 
         * @return builder
         * 
         */
        public Builder isGrpc(Boolean isGrpc) {
            return isGrpc(Output.of(isGrpc));
        }

        /**
         * @param isHostRewriteEnabled (Updatable) If true, the hostname will be rewritten to the target virtual deployment&#39;s DNS hostname.
         * 
         * @return builder
         * 
         */
        public Builder isHostRewriteEnabled(@Nullable Output<Boolean> isHostRewriteEnabled) {
            $.isHostRewriteEnabled = isHostRewriteEnabled;
            return this;
        }

        /**
         * @param isHostRewriteEnabled (Updatable) If true, the hostname will be rewritten to the target virtual deployment&#39;s DNS hostname.
         * 
         * @return builder
         * 
         */
        public Builder isHostRewriteEnabled(Boolean isHostRewriteEnabled) {
            return isHostRewriteEnabled(Output.of(isHostRewriteEnabled));
        }

        /**
         * @param isPathRewriteEnabled (Updatable) If true, the matched path prefix will be rewritten to &#39;/&#39; before being directed to the target virtual deployment.
         * 
         * @return builder
         * 
         */
        public Builder isPathRewriteEnabled(@Nullable Output<Boolean> isPathRewriteEnabled) {
            $.isPathRewriteEnabled = isPathRewriteEnabled;
            return this;
        }

        /**
         * @param isPathRewriteEnabled (Updatable) If true, the matched path prefix will be rewritten to &#39;/&#39; before being directed to the target virtual deployment.
         * 
         * @return builder
         * 
         */
        public Builder isPathRewriteEnabled(Boolean isPathRewriteEnabled) {
            return isPathRewriteEnabled(Output.of(isPathRewriteEnabled));
        }

        /**
         * @param path (Updatable) Route to match
         * 
         * @return builder
         * 
         */
        public Builder path(@Nullable Output<String> path) {
            $.path = path;
            return this;
        }

        /**
         * @param path (Updatable) Route to match
         * 
         * @return builder
         * 
         */
        public Builder path(String path) {
            return path(Output.of(path));
        }

        /**
         * @param pathType (Updatable) Match type for the route
         * 
         * @return builder
         * 
         */
        public Builder pathType(@Nullable Output<String> pathType) {
            $.pathType = pathType;
            return this;
        }

        /**
         * @param pathType (Updatable) Match type for the route
         * 
         * @return builder
         * 
         */
        public Builder pathType(String pathType) {
            return pathType(Output.of(pathType));
        }

        /**
         * @param type (Updatable) Type of protocol.
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) Type of protocol.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public IngressGatewayRouteTableRouteRuleArgs build() {
            $.destinations = Objects.requireNonNull($.destinations, "expected parameter 'destinations' to be non-null");
            $.type = Objects.requireNonNull($.type, "expected parameter 'type' to be non-null");
            return $;
        }
    }

}