// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.DeployEnvironmentComputeInstanceGroupSelectorsItem;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class DeployEnvironmentComputeInstanceGroupSelectors {
    /**
     * @return (Updatable) A list of selectors for the instance group. UNION operator is used for combining the instances selected by each selector.
     * 
     */
    private @Nullable List<DeployEnvironmentComputeInstanceGroupSelectorsItem> items;

    private DeployEnvironmentComputeInstanceGroupSelectors() {}
    /**
     * @return (Updatable) A list of selectors for the instance group. UNION operator is used for combining the instances selected by each selector.
     * 
     */
    public List<DeployEnvironmentComputeInstanceGroupSelectorsItem> items() {
        return this.items == null ? List.of() : this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DeployEnvironmentComputeInstanceGroupSelectors defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<DeployEnvironmentComputeInstanceGroupSelectorsItem> items;
        public Builder() {}
        public Builder(DeployEnvironmentComputeInstanceGroupSelectors defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(@Nullable List<DeployEnvironmentComputeInstanceGroupSelectorsItem> items) {
            this.items = items;
            return this;
        }
        public Builder items(DeployEnvironmentComputeInstanceGroupSelectorsItem... items) {
            return items(List.of(items));
        }
        public DeployEnvironmentComputeInstanceGroupSelectors build() {
            final var o = new DeployEnvironmentComputeInstanceGroupSelectors();
            o.items = items;
            return o;
        }
    }
}