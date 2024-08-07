// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DevOps.inputs.DeploymentDeployPipelineArtifactItemDeployPipelineStageItemArgs;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs Empty = new DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs();

    /**
     * A list of stage predecessors for a stage.
     * 
     */
    @Import(name="items")
    private @Nullable Output<List<DeploymentDeployPipelineArtifactItemDeployPipelineStageItemArgs>> items;

    /**
     * @return A list of stage predecessors for a stage.
     * 
     */
    public Optional<Output<List<DeploymentDeployPipelineArtifactItemDeployPipelineStageItemArgs>>> items() {
        return Optional.ofNullable(this.items);
    }

    private DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs() {}

    private DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs(DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs $) {
        this.items = $.items;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs $;

        public Builder() {
            $ = new DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs();
        }

        public Builder(DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs defaults) {
            $ = new DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param items A list of stage predecessors for a stage.
         * 
         * @return builder
         * 
         */
        public Builder items(@Nullable Output<List<DeploymentDeployPipelineArtifactItemDeployPipelineStageItemArgs>> items) {
            $.items = items;
            return this;
        }

        /**
         * @param items A list of stage predecessors for a stage.
         * 
         * @return builder
         * 
         */
        public Builder items(List<DeploymentDeployPipelineArtifactItemDeployPipelineStageItemArgs> items) {
            return items(Output.of(items));
        }

        /**
         * @param items A list of stage predecessors for a stage.
         * 
         * @return builder
         * 
         */
        public Builder items(DeploymentDeployPipelineArtifactItemDeployPipelineStageItemArgs... items) {
            return items(List.of(items));
        }

        public DeploymentDeployPipelineArtifactItemDeployPipelineStageArgs build() {
            return $;
        }
    }

}
