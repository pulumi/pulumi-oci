// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetDeploymentDeployPipelineEnvironmentItemDeployPipelineStage;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentDeployPipelineEnvironmentItem {
    /**
     * @return The OCID of an Environment
     * 
     */
    private String deployEnvironmentId;
    /**
     * @return List of stages.
     * 
     */
    private List<GetDeploymentDeployPipelineEnvironmentItemDeployPipelineStage> deployPipelineStages;
    /**
     * @return Deployment identifier which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    private String displayName;

    private GetDeploymentDeployPipelineEnvironmentItem() {}
    /**
     * @return The OCID of an Environment
     * 
     */
    public String deployEnvironmentId() {
        return this.deployEnvironmentId;
    }
    /**
     * @return List of stages.
     * 
     */
    public List<GetDeploymentDeployPipelineEnvironmentItemDeployPipelineStage> deployPipelineStages() {
        return this.deployPipelineStages;
    }
    /**
     * @return Deployment identifier which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentDeployPipelineEnvironmentItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String deployEnvironmentId;
        private List<GetDeploymentDeployPipelineEnvironmentItemDeployPipelineStage> deployPipelineStages;
        private String displayName;
        public Builder() {}
        public Builder(GetDeploymentDeployPipelineEnvironmentItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.deployEnvironmentId = defaults.deployEnvironmentId;
    	      this.deployPipelineStages = defaults.deployPipelineStages;
    	      this.displayName = defaults.displayName;
        }

        @CustomType.Setter
        public Builder deployEnvironmentId(String deployEnvironmentId) {
            this.deployEnvironmentId = Objects.requireNonNull(deployEnvironmentId);
            return this;
        }
        @CustomType.Setter
        public Builder deployPipelineStages(List<GetDeploymentDeployPipelineEnvironmentItemDeployPipelineStage> deployPipelineStages) {
            this.deployPipelineStages = Objects.requireNonNull(deployPipelineStages);
            return this;
        }
        public Builder deployPipelineStages(GetDeploymentDeployPipelineEnvironmentItemDeployPipelineStage... deployPipelineStages) {
            return deployPipelineStages(List.of(deployPipelineStages));
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        public GetDeploymentDeployPipelineEnvironmentItem build() {
            final var o = new GetDeploymentDeployPipelineEnvironmentItem();
            o.deployEnvironmentId = deployEnvironmentId;
            o.deployPipelineStages = deployPipelineStages;
            o.displayName = displayName;
            return o;
        }
    }
}