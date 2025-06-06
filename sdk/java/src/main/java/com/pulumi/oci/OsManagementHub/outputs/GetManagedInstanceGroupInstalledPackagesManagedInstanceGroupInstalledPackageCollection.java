// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.outputs.GetManagedInstanceGroupInstalledPackagesManagedInstanceGroupInstalledPackageCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagedInstanceGroupInstalledPackagesManagedInstanceGroupInstalledPackageCollection {
    /**
     * @return List of installed packages.
     * 
     */
    private List<GetManagedInstanceGroupInstalledPackagesManagedInstanceGroupInstalledPackageCollectionItem> items;

    private GetManagedInstanceGroupInstalledPackagesManagedInstanceGroupInstalledPackageCollection() {}
    /**
     * @return List of installed packages.
     * 
     */
    public List<GetManagedInstanceGroupInstalledPackagesManagedInstanceGroupInstalledPackageCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedInstanceGroupInstalledPackagesManagedInstanceGroupInstalledPackageCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetManagedInstanceGroupInstalledPackagesManagedInstanceGroupInstalledPackageCollectionItem> items;
        public Builder() {}
        public Builder(GetManagedInstanceGroupInstalledPackagesManagedInstanceGroupInstalledPackageCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetManagedInstanceGroupInstalledPackagesManagedInstanceGroupInstalledPackageCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceGroupInstalledPackagesManagedInstanceGroupInstalledPackageCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetManagedInstanceGroupInstalledPackagesManagedInstanceGroupInstalledPackageCollectionItem... items) {
            return items(List.of(items));
        }
        public GetManagedInstanceGroupInstalledPackagesManagedInstanceGroupInstalledPackageCollection build() {
            final var _resultValue = new GetManagedInstanceGroupInstalledPackagesManagedInstanceGroupInstalledPackageCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
