// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DevOps.inputs.DeployPipelineDeployPipelineEnvironmentItemArgs;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeployPipelineDeployPipelineEnvironmentArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeployPipelineDeployPipelineEnvironmentArgs Empty = new DeployPipelineDeployPipelineEnvironmentArgs();

    /**
     * List of parameters defined for a deployment pipeline.
     * 
     */
    @Import(name="items")
    private @Nullable Output<List<DeployPipelineDeployPipelineEnvironmentItemArgs>> items;

    /**
     * @return List of parameters defined for a deployment pipeline.
     * 
     */
    public Optional<Output<List<DeployPipelineDeployPipelineEnvironmentItemArgs>>> items() {
        return Optional.ofNullable(this.items);
    }

    private DeployPipelineDeployPipelineEnvironmentArgs() {}

    private DeployPipelineDeployPipelineEnvironmentArgs(DeployPipelineDeployPipelineEnvironmentArgs $) {
        this.items = $.items;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeployPipelineDeployPipelineEnvironmentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeployPipelineDeployPipelineEnvironmentArgs $;

        public Builder() {
            $ = new DeployPipelineDeployPipelineEnvironmentArgs();
        }

        public Builder(DeployPipelineDeployPipelineEnvironmentArgs defaults) {
            $ = new DeployPipelineDeployPipelineEnvironmentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param items List of parameters defined for a deployment pipeline.
         * 
         * @return builder
         * 
         */
        public Builder items(@Nullable Output<List<DeployPipelineDeployPipelineEnvironmentItemArgs>> items) {
            $.items = items;
            return this;
        }

        /**
         * @param items List of parameters defined for a deployment pipeline.
         * 
         * @return builder
         * 
         */
        public Builder items(List<DeployPipelineDeployPipelineEnvironmentItemArgs> items) {
            return items(Output.of(items));
        }

        /**
         * @param items List of parameters defined for a deployment pipeline.
         * 
         * @return builder
         * 
         */
        public Builder items(DeployPipelineDeployPipelineEnvironmentItemArgs... items) {
            return items(List.of(items));
        }

        public DeployPipelineDeployPipelineEnvironmentArgs build() {
            return $;
        }
    }

}
