// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetIngressGatewayArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetIngressGatewayArgs Empty = new GetIngressGatewayArgs();

    /**
     * Unique IngressGateway identifier.
     * 
     */
    @Import(name="ingressGatewayId", required=true)
    private Output<String> ingressGatewayId;

    /**
     * @return Unique IngressGateway identifier.
     * 
     */
    public Output<String> ingressGatewayId() {
        return this.ingressGatewayId;
    }

    private GetIngressGatewayArgs() {}

    private GetIngressGatewayArgs(GetIngressGatewayArgs $) {
        this.ingressGatewayId = $.ingressGatewayId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetIngressGatewayArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetIngressGatewayArgs $;

        public Builder() {
            $ = new GetIngressGatewayArgs();
        }

        public Builder(GetIngressGatewayArgs defaults) {
            $ = new GetIngressGatewayArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param ingressGatewayId Unique IngressGateway identifier.
         * 
         * @return builder
         * 
         */
        public Builder ingressGatewayId(Output<String> ingressGatewayId) {
            $.ingressGatewayId = ingressGatewayId;
            return this;
        }

        /**
         * @param ingressGatewayId Unique IngressGateway identifier.
         * 
         * @return builder
         * 
         */
        public Builder ingressGatewayId(String ingressGatewayId) {
            return ingressGatewayId(Output.of(ingressGatewayId));
        }

        public GetIngressGatewayArgs build() {
            $.ingressGatewayId = Objects.requireNonNull($.ingressGatewayId, "expected parameter 'ingressGatewayId' to be non-null");
            return $;
        }
    }

}