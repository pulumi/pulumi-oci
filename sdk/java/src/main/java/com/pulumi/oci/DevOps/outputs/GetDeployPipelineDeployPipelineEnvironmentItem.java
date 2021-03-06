// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetDeployPipelineDeployPipelineEnvironmentItemDeployPipelineStage;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeployPipelineDeployPipelineEnvironmentItem {
    /**
     * @return The OCID of an Environment
     * 
     */
    private final String deployEnvironmentId;
    /**
     * @return List of stages.
     * 
     */
    private final List<GetDeployPipelineDeployPipelineEnvironmentItemDeployPipelineStage> deployPipelineStages;
    /**
     * @return Deployment pipeline display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    private final String displayName;

    @CustomType.Constructor
    private GetDeployPipelineDeployPipelineEnvironmentItem(
        @CustomType.Parameter("deployEnvironmentId") String deployEnvironmentId,
        @CustomType.Parameter("deployPipelineStages") List<GetDeployPipelineDeployPipelineEnvironmentItemDeployPipelineStage> deployPipelineStages,
        @CustomType.Parameter("displayName") String displayName) {
        this.deployEnvironmentId = deployEnvironmentId;
        this.deployPipelineStages = deployPipelineStages;
        this.displayName = displayName;
    }

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
    public List<GetDeployPipelineDeployPipelineEnvironmentItemDeployPipelineStage> deployPipelineStages() {
        return this.deployPipelineStages;
    }
    /**
     * @return Deployment pipeline display name, which can be renamed and is not necessarily unique. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployPipelineDeployPipelineEnvironmentItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String deployEnvironmentId;
        private List<GetDeployPipelineDeployPipelineEnvironmentItemDeployPipelineStage> deployPipelineStages;
        private String displayName;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDeployPipelineDeployPipelineEnvironmentItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.deployEnvironmentId = defaults.deployEnvironmentId;
    	      this.deployPipelineStages = defaults.deployPipelineStages;
    	      this.displayName = defaults.displayName;
        }

        public Builder deployEnvironmentId(String deployEnvironmentId) {
            this.deployEnvironmentId = Objects.requireNonNull(deployEnvironmentId);
            return this;
        }
        public Builder deployPipelineStages(List<GetDeployPipelineDeployPipelineEnvironmentItemDeployPipelineStage> deployPipelineStages) {
            this.deployPipelineStages = Objects.requireNonNull(deployPipelineStages);
            return this;
        }
        public Builder deployPipelineStages(GetDeployPipelineDeployPipelineEnvironmentItemDeployPipelineStage... deployPipelineStages) {
            return deployPipelineStages(List.of(deployPipelineStages));
        }
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }        public GetDeployPipelineDeployPipelineEnvironmentItem build() {
            return new GetDeployPipelineDeployPipelineEnvironmentItem(deployEnvironmentId, deployPipelineStages, displayName);
        }
    }
}
