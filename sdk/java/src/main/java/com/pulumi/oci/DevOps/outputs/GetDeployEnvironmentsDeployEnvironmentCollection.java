// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.GetDeployEnvironmentsDeployEnvironmentCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDeployEnvironmentsDeployEnvironmentCollection {
    /**
     * @return A list of selectors for the instance group. UNION operator is used for combining the instances selected by each selector.
     * 
     */
    private List<GetDeployEnvironmentsDeployEnvironmentCollectionItem> items;

    private GetDeployEnvironmentsDeployEnvironmentCollection() {}
    /**
     * @return A list of selectors for the instance group. UNION operator is used for combining the instances selected by each selector.
     * 
     */
    public List<GetDeployEnvironmentsDeployEnvironmentCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployEnvironmentsDeployEnvironmentCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDeployEnvironmentsDeployEnvironmentCollectionItem> items;
        public Builder() {}
        public Builder(GetDeployEnvironmentsDeployEnvironmentCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetDeployEnvironmentsDeployEnvironmentCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetDeployEnvironmentsDeployEnvironmentCollectionItem... items) {
            return items(List.of(items));
        }
        public GetDeployEnvironmentsDeployEnvironmentCollection build() {
            final var o = new GetDeployEnvironmentsDeployEnvironmentCollection();
            o.items = items;
            return o;
        }
    }
}