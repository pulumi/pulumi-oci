// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetResolverArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetResolverArgs Empty = new GetResolverArgs();

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
     * Value must be `PRIVATE` when listing private name resolvers.
     * 
     */
    @Import(name="scope")
    private @Nullable Output<String> scope;

    /**
     * @return Value must be `PRIVATE` when listing private name resolvers.
     * 
     */
    public Optional<Output<String>> scope() {
        return Optional.ofNullable(this.scope);
    }

    private GetResolverArgs() {}

    private GetResolverArgs(GetResolverArgs $) {
        this.resolverId = $.resolverId;
        this.scope = $.scope;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetResolverArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetResolverArgs $;

        public Builder() {
            $ = new GetResolverArgs();
        }

        public Builder(GetResolverArgs defaults) {
            $ = new GetResolverArgs(Objects.requireNonNull(defaults));
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
         * @param scope Value must be `PRIVATE` when listing private name resolvers.
         * 
         * @return builder
         * 
         */
        public Builder scope(@Nullable Output<String> scope) {
            $.scope = scope;
            return this;
        }

        /**
         * @param scope Value must be `PRIVATE` when listing private name resolvers.
         * 
         * @return builder
         * 
         */
        public Builder scope(String scope) {
            return scope(Output.of(scope));
        }

        public GetResolverArgs build() {
            $.resolverId = Objects.requireNonNull($.resolverId, "expected parameter 'resolverId' to be non-null");
            return $;
        }
    }

}