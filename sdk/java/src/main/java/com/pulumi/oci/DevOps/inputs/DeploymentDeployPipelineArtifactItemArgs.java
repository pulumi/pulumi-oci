// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DevOps.inputs.DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeploymentDeployPipelineArtifactItemArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeploymentDeployPipelineArtifactItemArgs Empty = new DeploymentDeployPipelineArtifactItemArgs();

    /**
     * The OCID of an artifact
     * 
     */
    @Import(name="deployArtifactId")
    private @Nullable Output<String> deployArtifactId;

    /**
     * @return The OCID of an artifact
     * 
     */
    public Optional<Output<String>> deployArtifactId() {
        return Optional.ofNullable(this.deployArtifactId);
    }

    /**
     * List of stages.
     * 
     */
    @Import(name="deployPipelineStages")
    private @Nullable Output<List<DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs>> deployPipelineStages;

    /**
     * @return List of stages.
     * 
     */
    public Optional<Output<List<DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs>>> deployPipelineStages() {
        return Optional.ofNullable(this.deployPipelineStages);
    }

    /**
     * (Updatable) Deployment display name. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) Deployment display name. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    private DeploymentDeployPipelineArtifactItemArgs() {}

    private DeploymentDeployPipelineArtifactItemArgs(DeploymentDeployPipelineArtifactItemArgs $) {
        this.deployArtifactId = $.deployArtifactId;
        this.deployPipelineStages = $.deployPipelineStages;
        this.displayName = $.displayName;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeploymentDeployPipelineArtifactItemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeploymentDeployPipelineArtifactItemArgs $;

        public Builder() {
            $ = new DeploymentDeployPipelineArtifactItemArgs();
        }

        public Builder(DeploymentDeployPipelineArtifactItemArgs defaults) {
            $ = new DeploymentDeployPipelineArtifactItemArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param deployArtifactId The OCID of an artifact
         * 
         * @return builder
         * 
         */
        public Builder deployArtifactId(@Nullable Output<String> deployArtifactId) {
            $.deployArtifactId = deployArtifactId;
            return this;
        }

        /**
         * @param deployArtifactId The OCID of an artifact
         * 
         * @return builder
         * 
         */
        public Builder deployArtifactId(String deployArtifactId) {
            return deployArtifactId(Output.of(deployArtifactId));
        }

        /**
         * @param deployPipelineStages List of stages.
         * 
         * @return builder
         * 
         */
        public Builder deployPipelineStages(@Nullable Output<List<DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs>> deployPipelineStages) {
            $.deployPipelineStages = deployPipelineStages;
            return this;
        }

        /**
         * @param deployPipelineStages List of stages.
         * 
         * @return builder
         * 
         */
        public Builder deployPipelineStages(List<DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs> deployPipelineStages) {
            return deployPipelineStages(Output.of(deployPipelineStages));
        }

        /**
         * @param deployPipelineStages List of stages.
         * 
         * @return builder
         * 
         */
        public Builder deployPipelineStages(DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs... deployPipelineStages) {
            return deployPipelineStages(List.of(deployPipelineStages));
        }

        /**
         * @param displayName (Updatable) Deployment display name. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Deployment display name. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public DeploymentDeployPipelineArtifactItemArgs build() {
            return $;
        }
    }

}
