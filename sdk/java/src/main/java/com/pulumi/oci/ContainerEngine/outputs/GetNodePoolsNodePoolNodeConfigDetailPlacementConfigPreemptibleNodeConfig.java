// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.ContainerEngine.outputs.GetNodePoolsNodePoolNodeConfigDetailPlacementConfigPreemptibleNodeConfigPreemptionAction;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNodePoolsNodePoolNodeConfigDetailPlacementConfigPreemptibleNodeConfig {
    /**
     * @return The action to run when the preemptible node is interrupted for eviction.
     * 
     */
    private List<GetNodePoolsNodePoolNodeConfigDetailPlacementConfigPreemptibleNodeConfigPreemptionAction> preemptionActions;

    private GetNodePoolsNodePoolNodeConfigDetailPlacementConfigPreemptibleNodeConfig() {}
    /**
     * @return The action to run when the preemptible node is interrupted for eviction.
     * 
     */
    public List<GetNodePoolsNodePoolNodeConfigDetailPlacementConfigPreemptibleNodeConfigPreemptionAction> preemptionActions() {
        return this.preemptionActions;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNodePoolsNodePoolNodeConfigDetailPlacementConfigPreemptibleNodeConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetNodePoolsNodePoolNodeConfigDetailPlacementConfigPreemptibleNodeConfigPreemptionAction> preemptionActions;
        public Builder() {}
        public Builder(GetNodePoolsNodePoolNodeConfigDetailPlacementConfigPreemptibleNodeConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.preemptionActions = defaults.preemptionActions;
        }

        @CustomType.Setter
        public Builder preemptionActions(List<GetNodePoolsNodePoolNodeConfigDetailPlacementConfigPreemptibleNodeConfigPreemptionAction> preemptionActions) {
            if (preemptionActions == null) {
              throw new MissingRequiredPropertyException("GetNodePoolsNodePoolNodeConfigDetailPlacementConfigPreemptibleNodeConfig", "preemptionActions");
            }
            this.preemptionActions = preemptionActions;
            return this;
        }
        public Builder preemptionActions(GetNodePoolsNodePoolNodeConfigDetailPlacementConfigPreemptibleNodeConfigPreemptionAction... preemptionActions) {
            return preemptionActions(List.of(preemptionActions));
        }
        public GetNodePoolsNodePoolNodeConfigDetailPlacementConfigPreemptibleNodeConfig build() {
            final var _resultValue = new GetNodePoolsNodePoolNodeConfigDetailPlacementConfigPreemptibleNodeConfig();
            _resultValue.preemptionActions = preemptionActions;
            return _resultValue;
        }
    }
}
