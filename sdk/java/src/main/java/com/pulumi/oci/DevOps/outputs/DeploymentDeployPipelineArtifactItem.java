// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.DeploymentDeployPipelineArtifactItemDeployPipelineStage;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DeploymentDeployPipelineArtifactItem {
    /**
     * @return The OCID of the artifact to which this parameter applies.
     * 
     */
    private @Nullable String deployArtifactId;
    /**
     * @return List of stages.
     * 
     */
    private @Nullable List<DeploymentDeployPipelineArtifactItemDeployPipelineStage> deployPipelineStages;
    /**
     * @return (Updatable) Deployment display name. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;

    private DeploymentDeployPipelineArtifactItem() {}
    /**
     * @return The OCID of the artifact to which this parameter applies.
     * 
     */
    public Optional<String> deployArtifactId() {
        return Optional.ofNullable(this.deployArtifactId);
    }
    /**
     * @return List of stages.
     * 
     */
    public List<DeploymentDeployPipelineArtifactItemDeployPipelineStage> deployPipelineStages() {
        return this.deployPipelineStages == null ? List.of() : this.deployPipelineStages;
    }
    /**
     * @return (Updatable) Deployment display name. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentDeployPipelineArtifactItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String deployArtifactId;
        private @Nullable List<DeploymentDeployPipelineArtifactItemDeployPipelineStage> deployPipelineStages;
        private @Nullable String displayName;
        public Builder() {}
        public Builder(DeploymentDeployPipelineArtifactItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.deployArtifactId = defaults.deployArtifactId;
    	      this.deployPipelineStages = defaults.deployPipelineStages;
    	      this.displayName = defaults.displayName;
        }

        @CustomType.Setter
        public Builder deployArtifactId(@Nullable String deployArtifactId) {
            this.deployArtifactId = deployArtifactId;
            return this;
        }
        @CustomType.Setter
        public Builder deployPipelineStages(@Nullable List<DeploymentDeployPipelineArtifactItemDeployPipelineStage> deployPipelineStages) {
            this.deployPipelineStages = deployPipelineStages;
            return this;
        }
        public Builder deployPipelineStages(DeploymentDeployPipelineArtifactItemDeployPipelineStage... deployPipelineStages) {
            return deployPipelineStages(List.of(deployPipelineStages));
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public DeploymentDeployPipelineArtifactItem build() {
            final var o = new DeploymentDeployPipelineArtifactItem();
            o.deployArtifactId = deployArtifactId;
            o.deployPipelineStages = deployPipelineStages;
            o.displayName = displayName;
            return o;
        }
    }
}