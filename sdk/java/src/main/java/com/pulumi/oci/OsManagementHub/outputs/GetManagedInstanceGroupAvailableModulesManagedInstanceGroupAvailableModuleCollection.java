// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.OsManagementHub.outputs.GetManagedInstanceGroupAvailableModulesManagedInstanceGroupAvailableModuleCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagedInstanceGroupAvailableModulesManagedInstanceGroupAvailableModuleCollection {
    /**
     * @return List of module stream profile.
     * 
     */
    private List<GetManagedInstanceGroupAvailableModulesManagedInstanceGroupAvailableModuleCollectionItem> items;

    private GetManagedInstanceGroupAvailableModulesManagedInstanceGroupAvailableModuleCollection() {}
    /**
     * @return List of module stream profile.
     * 
     */
    public List<GetManagedInstanceGroupAvailableModulesManagedInstanceGroupAvailableModuleCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedInstanceGroupAvailableModulesManagedInstanceGroupAvailableModuleCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetManagedInstanceGroupAvailableModulesManagedInstanceGroupAvailableModuleCollectionItem> items;
        public Builder() {}
        public Builder(GetManagedInstanceGroupAvailableModulesManagedInstanceGroupAvailableModuleCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetManagedInstanceGroupAvailableModulesManagedInstanceGroupAvailableModuleCollectionItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetManagedInstanceGroupAvailableModulesManagedInstanceGroupAvailableModuleCollectionItem... items) {
            return items(List.of(items));
        }
        public GetManagedInstanceGroupAvailableModulesManagedInstanceGroupAvailableModuleCollection build() {
            final var o = new GetManagedInstanceGroupAvailableModulesManagedInstanceGroupAvailableModuleCollection();
            o.items = items;
            return o;
        }
    }
}