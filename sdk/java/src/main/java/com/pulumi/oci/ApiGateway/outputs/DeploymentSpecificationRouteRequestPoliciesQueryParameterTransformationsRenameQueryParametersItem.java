// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsRenameQueryParametersItem {
    /**
     * @return (Updatable) The original case-sensitive name of the query parameter.  This name must be unique across transformation policies.
     * 
     */
    private String from;
    /**
     * @return (Updatable) The new name of the query parameter.  This name must be unique across transformation policies.
     * 
     */
    private String to;

    private DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsRenameQueryParametersItem() {}
    /**
     * @return (Updatable) The original case-sensitive name of the query parameter.  This name must be unique across transformation policies.
     * 
     */
    public String from() {
        return this.from;
    }
    /**
     * @return (Updatable) The new name of the query parameter.  This name must be unique across transformation policies.
     * 
     */
    public String to() {
        return this.to;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsRenameQueryParametersItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String from;
        private String to;
        public Builder() {}
        public Builder(DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsRenameQueryParametersItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.from = defaults.from;
    	      this.to = defaults.to;
        }

        @CustomType.Setter
        public Builder from(String from) {
            if (from == null) {
              throw new MissingRequiredPropertyException("DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsRenameQueryParametersItem", "from");
            }
            this.from = from;
            return this;
        }
        @CustomType.Setter
        public Builder to(String to) {
            if (to == null) {
              throw new MissingRequiredPropertyException("DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsRenameQueryParametersItem", "to");
            }
            this.to = to;
            return this;
        }
        public DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsRenameQueryParametersItem build() {
            final var _resultValue = new DeploymentSpecificationRouteRequestPoliciesQueryParameterTransformationsRenameQueryParametersItem();
            _resultValue.from = from;
            _resultValue.to = to;
            return _resultValue;
        }
    }
}
