// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DevOps.inputs.DeployPipelineDeployPipelineArtifactItemArgs;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeployPipelineDeployPipelineArtifactArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeployPipelineDeployPipelineArtifactArgs Empty = new DeployPipelineDeployPipelineArtifactArgs();

    /**
     * (Updatable) List of parameters defined for a deployment pipeline.
     * 
     */
    @Import(name="items")
    private @Nullable Output<List<DeployPipelineDeployPipelineArtifactItemArgs>> items;

    /**
     * @return (Updatable) List of parameters defined for a deployment pipeline.
     * 
     */
    public Optional<Output<List<DeployPipelineDeployPipelineArtifactItemArgs>>> items() {
        return Optional.ofNullable(this.items);
    }

    private DeployPipelineDeployPipelineArtifactArgs() {}

    private DeployPipelineDeployPipelineArtifactArgs(DeployPipelineDeployPipelineArtifactArgs $) {
        this.items = $.items;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeployPipelineDeployPipelineArtifactArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeployPipelineDeployPipelineArtifactArgs $;

        public Builder() {
            $ = new DeployPipelineDeployPipelineArtifactArgs();
        }

        public Builder(DeployPipelineDeployPipelineArtifactArgs defaults) {
            $ = new DeployPipelineDeployPipelineArtifactArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param items (Updatable) List of parameters defined for a deployment pipeline.
         * 
         * @return builder
         * 
         */
        public Builder items(@Nullable Output<List<DeployPipelineDeployPipelineArtifactItemArgs>> items) {
            $.items = items;
            return this;
        }

        /**
         * @param items (Updatable) List of parameters defined for a deployment pipeline.
         * 
         * @return builder
         * 
         */
        public Builder items(List<DeployPipelineDeployPipelineArtifactItemArgs> items) {
            return items(Output.of(items));
        }

        /**
         * @param items (Updatable) List of parameters defined for a deployment pipeline.
         * 
         * @return builder
         * 
         */
        public Builder items(DeployPipelineDeployPipelineArtifactItemArgs... items) {
            return items(List.of(items));
        }

        public DeployPipelineDeployPipelineArtifactArgs build() {
            return $;
        }
    }

}