// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DevOps.inputs.DeploymentDeployPipelineEnvironmentItemArgs;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DeploymentDeployPipelineEnvironmentArgs extends com.pulumi.resources.ResourceArgs {

    public static final DeploymentDeployPipelineEnvironmentArgs Empty = new DeploymentDeployPipelineEnvironmentArgs();

    /**
     * List of arguments provided at the time of deployment.
     * 
     */
    @Import(name="items")
    private @Nullable Output<List<DeploymentDeployPipelineEnvironmentItemArgs>> items;

    /**
     * @return List of arguments provided at the time of deployment.
     * 
     */
    public Optional<Output<List<DeploymentDeployPipelineEnvironmentItemArgs>>> items() {
        return Optional.ofNullable(this.items);
    }

    private DeploymentDeployPipelineEnvironmentArgs() {}

    private DeploymentDeployPipelineEnvironmentArgs(DeploymentDeployPipelineEnvironmentArgs $) {
        this.items = $.items;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DeploymentDeployPipelineEnvironmentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DeploymentDeployPipelineEnvironmentArgs $;

        public Builder() {
            $ = new DeploymentDeployPipelineEnvironmentArgs();
        }

        public Builder(DeploymentDeployPipelineEnvironmentArgs defaults) {
            $ = new DeploymentDeployPipelineEnvironmentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param items List of arguments provided at the time of deployment.
         * 
         * @return builder
         * 
         */
        public Builder items(@Nullable Output<List<DeploymentDeployPipelineEnvironmentItemArgs>> items) {
            $.items = items;
            return this;
        }

        /**
         * @param items List of arguments provided at the time of deployment.
         * 
         * @return builder
         * 
         */
        public Builder items(List<DeploymentDeployPipelineEnvironmentItemArgs> items) {
            return items(Output.of(items));
        }

        /**
         * @param items List of arguments provided at the time of deployment.
         * 
         * @return builder
         * 
         */
        public Builder items(DeploymentDeployPipelineEnvironmentItemArgs... items) {
            return items(List.of(items));
        }

        public DeploymentDeployPipelineEnvironmentArgs build() {
            return $;
        }
    }

}