// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeploymentSpecificationRouteRequestPoliciesHeaderValidationsHeaderArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeploymentSpecificationRouteRequestPoliciesHeaderValidationsHeaderArgs Empty = new DeploymentSpecificationRouteRequestPoliciesHeaderValidationsHeaderArgs();

    /**
     * (Updatable) Parameter name.
     * 
     */
    @Import(name="name", required=true)
    private Output<String> name;

    /**
     * @return (Updatable) Parameter name.
     * 
     */
    public Output<String> name() {
        return this.name;
    }

    /**
     * (Updatable) Determines if the header is required in the request.
     * 
     */
    @Import(name="required")
    private @Nullable Output<Boolean> required;

    /**
     * @return (Updatable) Determines if the header is required in the request.
     * 
     */
    public Optional<Output<Boolean>> required() {
        return Optional.ofNullable(this.required);
    }

    private DeploymentSpecificationRouteRequestPoliciesHeaderValidationsHeaderArgs() {}

    private DeploymentSpecificationRouteRequestPoliciesHeaderValidationsHeaderArgs(DeploymentSpecificationRouteRequestPoliciesHeaderValidationsHeaderArgs $) {
        this.name = $.name;
        this.required = $.required;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeploymentSpecificationRouteRequestPoliciesHeaderValidationsHeaderArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeploymentSpecificationRouteRequestPoliciesHeaderValidationsHeaderArgs $;

        public Builder() {
            $ = new DeploymentSpecificationRouteRequestPoliciesHeaderValidationsHeaderArgs();
        }

        public Builder(DeploymentSpecificationRouteRequestPoliciesHeaderValidationsHeaderArgs defaults) {
            $ = new DeploymentSpecificationRouteRequestPoliciesHeaderValidationsHeaderArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param name (Updatable) Parameter name.
         * 
         * @return builder
         * 
         */
        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) Parameter name.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param required (Updatable) Determines if the header is required in the request.
         * 
         * @return builder
         * 
         */
        public Builder required(@Nullable Output<Boolean> required) {
            $.required = required;
            return this;
        }

        /**
         * @param required (Updatable) Determines if the header is required in the request.
         * 
         * @return builder
         * 
         */
        public Builder required(Boolean required) {
            return required(Output.of(required));
        }

        public DeploymentSpecificationRouteRequestPoliciesHeaderValidationsHeaderArgs build() {
            if ($.name == null) {
                throw new MissingRequiredPropertyException("DeploymentSpecificationRouteRequestPoliciesHeaderValidationsHeaderArgs", "name");
            }
            return $;
        }
    }

}
