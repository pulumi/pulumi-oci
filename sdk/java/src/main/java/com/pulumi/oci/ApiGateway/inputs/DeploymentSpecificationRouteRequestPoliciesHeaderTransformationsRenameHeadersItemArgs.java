// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemArgs Empty = new DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemArgs();

    /**
     * (Updatable) The original case-insensitive name of the header.  This name must be unique across transformation policies.
     * 
     */
    @Import(name="from", required=true)
    private Output<String> from;

    /**
     * @return (Updatable) The original case-insensitive name of the header.  This name must be unique across transformation policies.
     * 
     */
    public Output<String> from() {
        return this.from;
    }

    /**
     * (Updatable) The new name of the header.  This name must be unique across transformation policies.
     * 
     */
    @Import(name="to", required=true)
    private Output<String> to;

    /**
     * @return (Updatable) The new name of the header.  This name must be unique across transformation policies.
     * 
     */
    public Output<String> to() {
        return this.to;
    }

    private DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemArgs() {}

    private DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemArgs(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemArgs $) {
        this.from = $.from;
        this.to = $.to;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemArgs $;

        public Builder() {
            $ = new DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemArgs();
        }

        public Builder(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemArgs defaults) {
            $ = new DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param from (Updatable) The original case-insensitive name of the header.  This name must be unique across transformation policies.
         * 
         * @return builder
         * 
         */
        public Builder from(Output<String> from) {
            $.from = from;
            return this;
        }

        /**
         * @param from (Updatable) The original case-insensitive name of the header.  This name must be unique across transformation policies.
         * 
         * @return builder
         * 
         */
        public Builder from(String from) {
            return from(Output.of(from));
        }

        /**
         * @param to (Updatable) The new name of the header.  This name must be unique across transformation policies.
         * 
         * @return builder
         * 
         */
        public Builder to(Output<String> to) {
            $.to = to;
            return this;
        }

        /**
         * @param to (Updatable) The new name of the header.  This name must be unique across transformation policies.
         * 
         * @return builder
         * 
         */
        public Builder to(String to) {
            return to(Output.of(to));
        }

        public DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemArgs build() {
            if ($.from == null) {
                throw new MissingRequiredPropertyException("DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemArgs", "from");
            }
            if ($.to == null) {
                throw new MissingRequiredPropertyException("DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsRenameHeadersItemArgs", "to");
            }
            return $;
        }
    }

}
