// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataScience.outputs.GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfigurationModelDeploymentInstanceShapeConfigDetail;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfiguration {
    /**
     * @return The shape used to launch the model deployment instances.
     * 
     */
    private String instanceShapeName;
    /**
     * @return Details for the model-deployment instance shape configuration.
     * 
     */
    private List<GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfigurationModelDeploymentInstanceShapeConfigDetail> modelDeploymentInstanceShapeConfigDetails;

    private GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfiguration() {}
    /**
     * @return The shape used to launch the model deployment instances.
     * 
     */
    public String instanceShapeName() {
        return this.instanceShapeName;
    }
    /**
     * @return Details for the model-deployment instance shape configuration.
     * 
     */
    public List<GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfigurationModelDeploymentInstanceShapeConfigDetail> modelDeploymentInstanceShapeConfigDetails() {
        return this.modelDeploymentInstanceShapeConfigDetails;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfiguration defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String instanceShapeName;
        private List<GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfigurationModelDeploymentInstanceShapeConfigDetail> modelDeploymentInstanceShapeConfigDetails;
        public Builder() {}
        public Builder(GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfiguration defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.instanceShapeName = defaults.instanceShapeName;
    	      this.modelDeploymentInstanceShapeConfigDetails = defaults.modelDeploymentInstanceShapeConfigDetails;
        }

        @CustomType.Setter
        public Builder instanceShapeName(String instanceShapeName) {
            this.instanceShapeName = Objects.requireNonNull(instanceShapeName);
            return this;
        }
        @CustomType.Setter
        public Builder modelDeploymentInstanceShapeConfigDetails(List<GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfigurationModelDeploymentInstanceShapeConfigDetail> modelDeploymentInstanceShapeConfigDetails) {
            this.modelDeploymentInstanceShapeConfigDetails = Objects.requireNonNull(modelDeploymentInstanceShapeConfigDetails);
            return this;
        }
        public Builder modelDeploymentInstanceShapeConfigDetails(GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfigurationModelDeploymentInstanceShapeConfigDetail... modelDeploymentInstanceShapeConfigDetails) {
            return modelDeploymentInstanceShapeConfigDetails(List.of(modelDeploymentInstanceShapeConfigDetails));
        }
        public GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfiguration build() {
            final var o = new GetModelDeploymentsModelDeploymentModelDeploymentConfigurationDetailModelConfigurationDetailInstanceConfiguration();
            o.instanceShapeName = instanceShapeName;
            o.modelDeploymentInstanceShapeConfigDetails = modelDeploymentInstanceShapeConfigDetails;
            return o;
        }
    }
}