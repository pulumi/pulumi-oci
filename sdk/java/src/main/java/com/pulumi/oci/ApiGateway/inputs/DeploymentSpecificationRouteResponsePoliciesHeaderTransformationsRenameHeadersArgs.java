// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersItemArgs;
import java.util.List;
import java.util.Objects;


public final class DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs Empty = new DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs();

    /**
     * (Updatable) The list of headers.
     * 
     */
    @Import(name="items", required=true)
    private Output<List<DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersItemArgs>> items;

    /**
     * @return (Updatable) The list of headers.
     * 
     */
    public Output<List<DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersItemArgs>> items() {
        return this.items;
    }

    private DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs() {}

    private DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs $) {
        this.items = $.items;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs $;

        public Builder() {
            $ = new DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs();
        }

        public Builder(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs defaults) {
            $ = new DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param items (Updatable) The list of headers.
         * 
         * @return builder
         * 
         */
        public Builder items(Output<List<DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersItemArgs>> items) {
            $.items = items;
            return this;
        }

        /**
         * @param items (Updatable) The list of headers.
         * 
         * @return builder
         * 
         */
        public Builder items(List<DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersItemArgs> items) {
            return items(Output.of(items));
        }

        /**
         * @param items (Updatable) The list of headers.
         * 
         * @return builder
         * 
         */
        public Builder items(DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersItemArgs... items) {
            return items(List.of(items));
        }

        public DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs build() {
            if ($.items == null) {
                throw new MissingRequiredPropertyException("DeploymentSpecificationRouteResponsePoliciesHeaderTransformationsRenameHeadersArgs", "items");
            }
            return $;
        }
    }

}
