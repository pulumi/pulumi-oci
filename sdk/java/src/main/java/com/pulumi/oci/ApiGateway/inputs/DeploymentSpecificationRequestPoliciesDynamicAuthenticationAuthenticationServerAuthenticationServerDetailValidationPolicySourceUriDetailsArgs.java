// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetailsArgs Empty = new DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetailsArgs();

    /**
     * (Updatable) Type of the Response Cache Store Policy.
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return (Updatable) Type of the Response Cache Store Policy.
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    /**
     * (Updatable) The uri from which to retrieve the key. It must be accessible without authentication.
     * 
     */
    @Import(name="uri")
    private @Nullable Output<String> uri;

    /**
     * @return (Updatable) The uri from which to retrieve the key. It must be accessible without authentication.
     * 
     */
    public Optional<Output<String>> uri() {
        return Optional.ofNullable(this.uri);
    }

    private DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetailsArgs() {}

    private DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetailsArgs(DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetailsArgs $) {
        this.type = $.type;
        this.uri = $.uri;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetailsArgs $;

        public Builder() {
            $ = new DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetailsArgs();
        }

        public Builder(DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetailsArgs defaults) {
            $ = new DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param type (Updatable) Type of the Response Cache Store Policy.
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) Type of the Response Cache Store Policy.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        /**
         * @param uri (Updatable) The uri from which to retrieve the key. It must be accessible without authentication.
         * 
         * @return builder
         * 
         */
        public Builder uri(@Nullable Output<String> uri) {
            $.uri = uri;
            return this;
        }

        /**
         * @param uri (Updatable) The uri from which to retrieve the key. It must be accessible without authentication.
         * 
         * @return builder
         * 
         */
        public Builder uri(String uri) {
            return uri(Output.of(uri));
        }

        public DeploymentSpecificationRequestPoliciesDynamicAuthenticationAuthenticationServerAuthenticationServerDetailValidationPolicySourceUriDetailsArgs build() {
            $.type = Objects.requireNonNull($.type, "expected parameter 'type' to be non-null");
            return $;
        }
    }

}