// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersItemArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;


public final class DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersArgs Empty = new DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersArgs();

    /**
     * (Updatable) The list of headers.
     * 
     */
    @Import(name="items", required=true)
    private Output<List<DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersItemArgs>> items;

    /**
     * @return (Updatable) The list of headers.
     * 
     */
    public Output<List<DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersItemArgs>> items() {
        return this.items;
    }

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

    private DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersArgs() {}

    private DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersArgs(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersArgs $) {
        this.items = $.items;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersArgs $;

        public Builder() {
            $ = new DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersArgs();
        }

        public Builder(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersArgs defaults) {
            $ = new DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param items (Updatable) The list of headers.
         * 
         * @return builder
         * 
         */
        public Builder items(Output<List<DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersItemArgs>> items) {
            $.items = items;
            return this;
        }

        /**
         * @param items (Updatable) The list of headers.
         * 
         * @return builder
         * 
         */
        public Builder items(List<DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersItemArgs> items) {
            return items(Output.of(items));
        }

        /**
         * @param items (Updatable) The list of headers.
         * 
         * @return builder
         * 
         */
        public Builder items(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersItemArgs... items) {
            return items(List.of(items));
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

        public DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsFilterQueryParametersArgs build() {
            $.items = Objects.requireNonNull($.items, "expected parameter 'items' to be non-null");
            $.type = Objects.requireNonNull($.type, "expected parameter 'type' to be non-null");
            return $;
        }
    }

}
