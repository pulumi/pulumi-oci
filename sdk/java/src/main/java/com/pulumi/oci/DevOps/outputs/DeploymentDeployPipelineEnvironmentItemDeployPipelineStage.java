// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.DeploymentDeployPipelineEnvironmentItemDeployPipelineStageItem;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class DeploymentDeployPipelineEnvironmentItemDeployPipelineStage {
    /**
     * @return List of arguments provided at the time of deployment.
     * 
     */
    private @Nullable List<DeploymentDeployPipelineEnvironmentItemDeployPipelineStageItem> items;

    private DeploymentDeployPipelineEnvironmentItemDeployPipelineStage() {}
    /**
     * @return List of arguments provided at the time of deployment.
     * 
     */
    public List<DeploymentDeployPipelineEnvironmentItemDeployPipelineStageItem> items() {
        return this.items == null ? List.of() : this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeploymentDeployPipelineEnvironmentItemDeployPipelineStage defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<DeploymentDeployPipelineEnvironmentItemDeployPipelineStageItem> items;
        public Builder() {}
        public Builder(DeploymentDeployPipelineEnvironmentItemDeployPipelineStage defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(@Nullable List<DeploymentDeployPipelineEnvironmentItemDeployPipelineStageItem> items) {
            this.items = items;
            return this;
        }
        public Builder items(DeploymentDeployPipelineEnvironmentItemDeployPipelineStageItem... items) {
            return items(List.of(items));
        }
        public DeploymentDeployPipelineEnvironmentItemDeployPipelineStage build() {
            final var o = new DeploymentDeployPipelineEnvironmentItemDeployPipelineStage();
            o.items = items;
            return o;
        }
    }
}