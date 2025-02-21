// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsParameter {
    /**
     * @return (Updatable) Parameter name.
     * 
     */
    private String name;
    /**
     * @return (Updatable) Determines if the parameter is required in the request.
     * 
     */
    private @Nullable Boolean required;

    private DeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsParameter() {}
    /**
     * @return (Updatable) Parameter name.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return (Updatable) Determines if the parameter is required in the request.
     * 
     */
    public Optional<Boolean> required() {
        return Optional.ofNullable(this.required);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsParameter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private @Nullable Boolean required;
        public Builder() {}
        public Builder(DeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsParameter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.required = defaults.required;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("DeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsParameter", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder required(@Nullable Boolean required) {

            this.required = required;
            return this;
        }
        public DeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsParameter build() {
            final var _resultValue = new DeploymentSpecificationRouteRequestPoliciesQueryParameterValidationsParameter();
            _resultValue.name = name;
            _resultValue.required = required;
            return _resultValue;
        }
    }
}
