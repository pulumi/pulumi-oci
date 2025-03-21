// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.outputs.GetModelDeploymentModelDeploymentConfigurationDetailEnvironmentConfigurationDetail;
import com.pulumi.oci.DataScience.outputs.GetModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetModelDeploymentModelDeploymentConfigurationDetail {
    /**
     * @return The type of the model deployment.
     * 
     */
    private String deploymentType;
    /**
     * @return The configuration to carry the environment details thats used in Model Deployment creation
     * 
     */
    private List<GetModelDeploymentModelDeploymentConfigurationDetailEnvironmentConfigurationDetail> environmentConfigurationDetails;
    /**
     * @return The model configuration details.
     * 
     */
    private List<GetModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetail> modelConfigurationDetails;

    private GetModelDeploymentModelDeploymentConfigurationDetail() {}
    /**
     * @return The type of the model deployment.
     * 
     */
    public String deploymentType() {
        return this.deploymentType;
    }
    /**
     * @return The configuration to carry the environment details thats used in Model Deployment creation
     * 
     */
    public List<GetModelDeploymentModelDeploymentConfigurationDetailEnvironmentConfigurationDetail> environmentConfigurationDetails() {
        return this.environmentConfigurationDetails;
    }
    /**
     * @return The model configuration details.
     * 
     */
    public List<GetModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetail> modelConfigurationDetails() {
        return this.modelConfigurationDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelDeploymentModelDeploymentConfigurationDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String deploymentType;
        private List<GetModelDeploymentModelDeploymentConfigurationDetailEnvironmentConfigurationDetail> environmentConfigurationDetails;
        private List<GetModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetail> modelConfigurationDetails;
        public Builder() {}
        public Builder(GetModelDeploymentModelDeploymentConfigurationDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.deploymentType = defaults.deploymentType;
    	      this.environmentConfigurationDetails = defaults.environmentConfigurationDetails;
    	      this.modelConfigurationDetails = defaults.modelConfigurationDetails;
        }

        @CustomType.Setter
        public Builder deploymentType(String deploymentType) {
            if (deploymentType == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentModelDeploymentConfigurationDetail", "deploymentType");
            }
            this.deploymentType = deploymentType;
            return this;
        }
        @CustomType.Setter
        public Builder environmentConfigurationDetails(List<GetModelDeploymentModelDeploymentConfigurationDetailEnvironmentConfigurationDetail> environmentConfigurationDetails) {
            if (environmentConfigurationDetails == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentModelDeploymentConfigurationDetail", "environmentConfigurationDetails");
            }
            this.environmentConfigurationDetails = environmentConfigurationDetails;
            return this;
        }
        public Builder environmentConfigurationDetails(GetModelDeploymentModelDeploymentConfigurationDetailEnvironmentConfigurationDetail... environmentConfigurationDetails) {
            return environmentConfigurationDetails(List.of(environmentConfigurationDetails));
        }
        @CustomType.Setter
        public Builder modelConfigurationDetails(List<GetModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetail> modelConfigurationDetails) {
            if (modelConfigurationDetails == null) {
              throw new MissingRequiredPropertyException("GetModelDeploymentModelDeploymentConfigurationDetail", "modelConfigurationDetails");
            }
            this.modelConfigurationDetails = modelConfigurationDetails;
            return this;
        }
        public Builder modelConfigurationDetails(GetModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetail... modelConfigurationDetails) {
            return modelConfigurationDetails(List.of(modelConfigurationDetails));
        }
        public GetModelDeploymentModelDeploymentConfigurationDetail build() {
            final var _resultValue = new GetModelDeploymentModelDeploymentConfigurationDetail();
            _resultValue.deploymentType = deploymentType;
            _resultValue.environmentConfigurationDetails = environmentConfigurationDetails;
            _resultValue.modelConfigurationDetails = modelConfigurationDetails;
            return _resultValue;
        }
    }
}
