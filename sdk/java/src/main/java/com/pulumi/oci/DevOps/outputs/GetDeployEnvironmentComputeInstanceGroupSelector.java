// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DevOps.outputs.GetDeployEnvironmentComputeInstanceGroupSelectorItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeployEnvironmentComputeInstanceGroupSelector {
    /**
     * @return A list of selectors for the instance group. UNION operator is used for combining the instances selected by each selector.
     * 
     */
    private List<GetDeployEnvironmentComputeInstanceGroupSelectorItem> items;

    private GetDeployEnvironmentComputeInstanceGroupSelector() {}
    /**
     * @return A list of selectors for the instance group. UNION operator is used for combining the instances selected by each selector.
     * 
     */
    public List<GetDeployEnvironmentComputeInstanceGroupSelectorItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployEnvironmentComputeInstanceGroupSelector defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeployEnvironmentComputeInstanceGroupSelectorItem> items;
        public Builder() {}
        public Builder(GetDeployEnvironmentComputeInstanceGroupSelector defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDeployEnvironmentComputeInstanceGroupSelectorItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetDeployEnvironmentComputeInstanceGroupSelector", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetDeployEnvironmentComputeInstanceGroupSelectorItem... items) {
            return items(List.of(items));
        }
        public GetDeployEnvironmentComputeInstanceGroupSelector build() {
            final var _resultValue = new GetDeployEnvironmentComputeInstanceGroupSelector();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
