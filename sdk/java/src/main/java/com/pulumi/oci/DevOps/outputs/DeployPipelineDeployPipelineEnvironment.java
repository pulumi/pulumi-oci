// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.DeployPipelineDeployPipelineEnvironmentItem;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class DeployPipelineDeployPipelineEnvironment {
    /**
     * @return (Updatable) List of parameters defined for a deployment pipeline.
     * 
     */
    private final @Nullable List<DeployPipelineDeployPipelineEnvironmentItem> items;

    @CustomType.Constructor
    private DeployPipelineDeployPipelineEnvironment(@CustomType.Parameter("items") @Nullable List<DeployPipelineDeployPipelineEnvironmentItem> items) {
        this.items = items;
    }

    /**
     * @return (Updatable) List of parameters defined for a deployment pipeline.
     * 
     */
    public List<DeployPipelineDeployPipelineEnvironmentItem> items() {
        return this.items == null ? List.of() : this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeployPipelineDeployPipelineEnvironment defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable List<DeployPipelineDeployPipelineEnvironmentItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(DeployPipelineDeployPipelineEnvironment defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(@Nullable List<DeployPipelineDeployPipelineEnvironmentItem> items) {
            this.items = items;
            return this;
        }
        public Builder items(DeployPipelineDeployPipelineEnvironmentItem... items) {
            return items(List.of(items));
        }        public DeployPipelineDeployPipelineEnvironment build() {
            return new DeployPipelineDeployPipelineEnvironment(items);
        }
    }
}
