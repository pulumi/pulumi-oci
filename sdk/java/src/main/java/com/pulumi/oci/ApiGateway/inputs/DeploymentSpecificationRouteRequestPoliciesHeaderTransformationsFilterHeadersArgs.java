// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ApiGateway.inputs.DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersItemArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;


public final class DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs Empty = new DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs();

    /**
     * (Updatable) The list of headers.
     * 
     */
    @Import(name="items", required=true)
    private Output<List<DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersItemArgs>> items;

    /**
     * @return (Updatable) The list of headers.
     * 
     */
    public Output<List<DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersItemArgs>> items() {
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

    private DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs() {}

    private DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs $) {
        this.items = $.items;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs $;

        public Builder() {
            $ = new DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs();
        }

        public Builder(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs defaults) {
            $ = new DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param items (Updatable) The list of headers.
         * 
         * @return builder
         * 
         */
        public Builder items(Output<List<DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersItemArgs>> items) {
            $.items = items;
            return this;
        }

        /**
         * @param items (Updatable) The list of headers.
         * 
         * @return builder
         * 
         */
        public Builder items(List<DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersItemArgs> items) {
            return items(Output.of(items));
        }

        /**
         * @param items (Updatable) The list of headers.
         * 
         * @return builder
         * 
         */
        public Builder items(DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersItemArgs... items) {
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

        public DeploymentSpecificationRouteRequestPoliciesHeaderTransformationsFilterHeadersArgs build() {
            $.items = Objects.requireNonNull($.items, "expected parameter 'items' to be non-null");
            $.type = Objects.requireNonNull($.type, "expected parameter 'type' to be non-null");
            return $;
        }
    }

}