// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironmentItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironment {
    /**
     * @return A list of stage predecessors for a stage.
     * 
     */
    private final List<GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironmentItem> items;

    @CustomType.Constructor
    private GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironment(@CustomType.Parameter("items") List<GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironmentItem> items) {
        this.items = items;
    }

    /**
     * @return A list of stage predecessors for a stage.
     * 
     */
    public List<GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironmentItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironment defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironmentItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironment defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironmentItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironmentItem... items) {
            return items(List.of(items));
        }        public GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironment build() {
            return new GetDeploymentsDeploymentCollectionItemDeployPipelineEnvironment(items);
        }
    }
}
