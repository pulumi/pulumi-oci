// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.DeployPipelineDeployPipelineArtifactItemDeployPipelineStage;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DeployPipelineDeployPipelineArtifactItem {
    /**
     * @return The OCID of an artifact
     * 
     */
    private final @Nullable String deployArtifactId;
    /**
     * @return List of stages.
     * 
     */
    private final @Nullable List<DeployPipelineDeployPipelineArtifactItemDeployPipelineStage> deployPipelineStages;
    /**
     * @return (Updatable) Deployment pipeline display name. Avoid entering confidential information.
     * 
     */
    private final @Nullable String displayName;

    @CustomType.Constructor
    private DeployPipelineDeployPipelineArtifactItem(
        @CustomType.Parameter("deployArtifactId") @Nullable String deployArtifactId,
        @CustomType.Parameter("deployPipelineStages") @Nullable List<DeployPipelineDeployPipelineArtifactItemDeployPipelineStage> deployPipelineStages,
        @CustomType.Parameter("displayName") @Nullable String displayName) {
        this.deployArtifactId = deployArtifactId;
        this.deployPipelineStages = deployPipelineStages;
        this.displayName = displayName;
    }

    /**
     * @return The OCID of an artifact
     * 
     */
    public Optional<String> deployArtifactId() {
        return Optional.ofNullable(this.deployArtifactId);
    }
    /**
     * @return List of stages.
     * 
     */
    public List<DeployPipelineDeployPipelineArtifactItemDeployPipelineStage> deployPipelineStages() {
        return this.deployPipelineStages == null ? List.of() : this.deployPipelineStages;
    }
    /**
     * @return (Updatable) Deployment pipeline display name. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeployPipelineDeployPipelineArtifactItem defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String deployArtifactId;
        private @Nullable List<DeployPipelineDeployPipelineArtifactItemDeployPipelineStage> deployPipelineStages;
        private @Nullable String displayName;

        public Builder() {
    	      // Empty
        }

        public Builder(DeployPipelineDeployPipelineArtifactItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.deployArtifactId = defaults.deployArtifactId;
    	      this.deployPipelineStages = defaults.deployPipelineStages;
    	      this.displayName = defaults.displayName;
        }

        public Builder deployArtifactId(@Nullable String deployArtifactId) {
            this.deployArtifactId = deployArtifactId;
            return this;
        }
        public Builder deployPipelineStages(@Nullable List<DeployPipelineDeployPipelineArtifactItemDeployPipelineStage> deployPipelineStages) {
            this.deployPipelineStages = deployPipelineStages;
            return this;
        }
        public Builder deployPipelineStages(DeployPipelineDeployPipelineArtifactItemDeployPipelineStage... deployPipelineStages) {
            return deployPipelineStages(List.of(deployPipelineStages));
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }        public DeployPipelineDeployPipelineArtifactItem build() {
            return new DeployPipelineDeployPipelineArtifactItem(deployArtifactId, deployPipelineStages, displayName);
        }
    }
}
