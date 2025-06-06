// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ApiGateway.outputs.GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyBodyValidationContent;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyBodyValidation {
    /**
     * @return The content of the request body.
     * 
     */
    private List<GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyBodyValidationContent> contents;
    /**
     * @return Determines if the parameter is required in the request.
     * 
     */
    private Boolean required;
    /**
     * @return Validation behavior mode.
     * 
     */
    private String validationMode;

    private GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyBodyValidation() {}
    /**
     * @return The content of the request body.
     * 
     */
    public List<GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyBodyValidationContent> contents() {
        return this.contents;
    }
    /**
     * @return Determines if the parameter is required in the request.
     * 
     */
    public Boolean required() {
        return this.required;
    }
    /**
     * @return Validation behavior mode.
     * 
     */
    public String validationMode() {
        return this.validationMode;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyBodyValidation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyBodyValidationContent> contents;
        private Boolean required;
        private String validationMode;
        public Builder() {}
        public Builder(GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyBodyValidation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.contents = defaults.contents;
    	      this.required = defaults.required;
    	      this.validationMode = defaults.validationMode;
        }

        @CustomType.Setter
        public Builder contents(List<GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyBodyValidationContent> contents) {
            if (contents == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyBodyValidation", "contents");
            }
            this.contents = contents;
            return this;
        }
        public Builder contents(GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyBodyValidationContent... contents) {
            return contents(List.of(contents));
        }
        @CustomType.Setter
        public Builder required(Boolean required) {
            if (required == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyBodyValidation", "required");
            }
            this.required = required;
            return this;
        }
        @CustomType.Setter
        public Builder validationMode(String validationMode) {
            if (validationMode == null) {
              throw new MissingRequiredPropertyException("GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyBodyValidation", "validationMode");
            }
            this.validationMode = validationMode;
            return this;
        }
        public GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyBodyValidation build() {
            final var _resultValue = new GetDeploymentsDeploymentCollectionSpecificationRouteRequestPolicyBodyValidation();
            _resultValue.contents = contents;
            _resultValue.required = required;
            _resultValue.validationMode = validationMode;
            return _resultValue;
        }
    }
}
