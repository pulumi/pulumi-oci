// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsFilterHeadersArgs;
import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs;
import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeadersArgs;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsArgs Empty = new DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsArgs();

    /**
     * (Updatable) Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    @Import(name="filterHeaders")
    private @Nullable Output<DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsFilterHeadersArgs> filterHeaders;

    /**
     * @return (Updatable) Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
     * 
     */
    public Optional<Output<DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsFilterHeadersArgs>> filterHeaders() {
        return Optional.ofNullable(this.filterHeaders);
    }

    /**
     * (Updatable) Rename HTTP headers as they pass through the gateway.
     * 
     */
    @Import(name="renameHeaders")
    private @Nullable Output<DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs> renameHeaders;

    /**
     * @return (Updatable) Rename HTTP headers as they pass through the gateway.
     * 
     */
    public Optional<Output<DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs>> renameHeaders() {
        return Optional.ofNullable(this.renameHeaders);
    }

    /**
     * (Updatable) Set HTTP headers as they pass through the gateway.
     * 
     */
    @Import(name="setHeaders")
    private @Nullable Output<DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeadersArgs> setHeaders;

    /**
     * @return (Updatable) Set HTTP headers as they pass through the gateway.
     * 
     */
    public Optional<Output<DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeadersArgs>> setHeaders() {
        return Optional.ofNullable(this.setHeaders);
    }

    private DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsArgs() {}

    private DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsArgs(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsArgs $) {
        this.filterHeaders = $.filterHeaders;
        this.renameHeaders = $.renameHeaders;
        this.setHeaders = $.setHeaders;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsArgs $;

        public Builder() {
            $ = new DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsArgs();
        }

        public Builder(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsArgs defaults) {
            $ = new DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param filterHeaders (Updatable) Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
         * 
         * @return builder
         * 
         */
        public Builder filterHeaders(@Nullable Output<DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsFilterHeadersArgs> filterHeaders) {
            $.filterHeaders = filterHeaders;
            return this;
        }

        /**
         * @param filterHeaders (Updatable) Filter HTTP headers as they pass through the gateway.  The gateway applies filters after other transformations, so any headers set or renamed must also be listed here when using an ALLOW type policy.
         * 
         * @return builder
         * 
         */
        public Builder filterHeaders(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsFilterHeadersArgs filterHeaders) {
            return filterHeaders(Output.of(filterHeaders));
        }

        /**
         * @param renameHeaders (Updatable) Rename HTTP headers as they pass through the gateway.
         * 
         * @return builder
         * 
         */
        public Builder renameHeaders(@Nullable Output<DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs> renameHeaders) {
            $.renameHeaders = renameHeaders;
            return this;
        }

        /**
         * @param renameHeaders (Updatable) Rename HTTP headers as they pass through the gateway.
         * 
         * @return builder
         * 
         */
        public Builder renameHeaders(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs renameHeaders) {
            return renameHeaders(Output.of(renameHeaders));
        }

        /**
         * @param setHeaders (Updatable) Set HTTP headers as they pass through the gateway.
         * 
         * @return builder
         * 
         */
        public Builder setHeaders(@Nullable Output<DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeadersArgs> setHeaders) {
            $.setHeaders = setHeaders;
            return this;
        }

        /**
         * @param setHeaders (Updatable) Set HTTP headers as they pass through the gateway.
         * 
         * @return builder
         * 
         */
        public Builder setHeaders(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsSetHeadersArgs setHeaders) {
            return setHeaders(Output.of(setHeaders));
        }

        public DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsArgs build() {
            return $;
        }
    }

}
