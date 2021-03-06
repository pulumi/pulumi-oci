// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetResolverEndpointArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetResolverEndpointArgs Empty = new GetResolverEndpointArgs();

    /**
     * The name of the target resolver endpoint.
     * 
     */
    @Import(name="resolverEndpointName", required=true)
    private Output<String> resolverEndpointName;

    /**
     * @return The name of the target resolver endpoint.
     * 
     */
    public Output<String> resolverEndpointName() {
        return this.resolverEndpointName;
    }

    /**
     * The OCID of the target resolver.
     * 
     */
    @Import(name="resolverId", required=true)
    private Output<String> resolverId;

    /**
     * @return The OCID of the target resolver.
     * 
     */
    public Output<String> resolverId() {
        return this.resolverId;
    }

    /**
     * Value must be `PRIVATE` when listing private name resolver endpoints.
     * 
     */
    @Import(name="scope", required=true)
    private Output<String> scope;

    /**
     * @return Value must be `PRIVATE` when listing private name resolver endpoints.
     * 
     */
    public Output<String> scope() {
        return this.scope;
    }

    private GetResolverEndpointArgs() {}

    private GetResolverEndpointArgs(GetResolverEndpointArgs $) {
        this.resolverEndpointName = $.resolverEndpointName;
        this.resolverId = $.resolverId;
        this.scope = $.scope;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetResolverEndpointArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetResolverEndpointArgs $;

        public Builder() {
            $ = new GetResolverEndpointArgs();
        }

        public Builder(GetResolverEndpointArgs defaults) {
            $ = new GetResolverEndpointArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param resolverEndpointName The name of the target resolver endpoint.
         * 
         * @return builder
         * 
         */
        public Builder resolverEndpointName(Output<String> resolverEndpointName) {
            $.resolverEndpointName = resolverEndpointName;
            return this;
        }

        /**
         * @param resolverEndpointName The name of the target resolver endpoint.
         * 
         * @return builder
         * 
         */
        public Builder resolverEndpointName(String resolverEndpointName) {
            return resolverEndpointName(Output.of(resolverEndpointName));
        }

        /**
         * @param resolverId The OCID of the target resolver.
         * 
         * @return builder
         * 
         */
        public Builder resolverId(Output<String> resolverId) {
            $.resolverId = resolverId;
            return this;
        }

        /**
         * @param resolverId The OCID of the target resolver.
         * 
         * @return builder
         * 
         */
        public Builder resolverId(String resolverId) {
            return resolverId(Output.of(resolverId));
        }

        /**
         * @param scope Value must be `PRIVATE` when listing private name resolver endpoints.
         * 
         * @return builder
         * 
         */
        public Builder scope(Output<String> scope) {
            $.scope = scope;
            return this;
        }

        /**
         * @param scope Value must be `PRIVATE` when listing private name resolver endpoints.
         * 
         * @return builder
         * 
         */
        public Builder scope(String scope) {
            return scope(Output.of(scope));
        }

        public GetResolverEndpointArgs build() {
            $.resolverEndpointName = Objects.requireNonNull($.resolverEndpointName, "expected parameter 'resolverEndpointName' to be non-null");
            $.resolverId = Objects.requireNonNull($.resolverId, "expected parameter 'resolverId' to be non-null");
            $.scope = Objects.requireNonNull($.scope, "expected parameter 'scope' to be non-null");
            return $;
        }
    }

}
