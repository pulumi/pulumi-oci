// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.OsManagementHub.outputs.GetManagedInstanceGroupAvailablePackagesFilter;
import com.pulumi.oci.OsManagementHub.outputs.GetManagedInstanceGroupAvailablePackagesManagedInstanceGroupAvailablePackageCollection;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetManagedInstanceGroupAvailablePackagesResult {
    private @Nullable String compartmentId;
    private @Nullable String displayNameContains;
    /**
     * @return Software source name.
     * 
     */
    private @Nullable List<String> displayNames;
    private @Nullable List<GetManagedInstanceGroupAvailablePackagesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Flag to return only latest package versions.
     * 
     */
    private @Nullable Boolean isLatest;
    /**
     * @return The list of managed_instance_group_available_package_collection.
     * 
     */
    private List<GetManagedInstanceGroupAvailablePackagesManagedInstanceGroupAvailablePackageCollection> managedInstanceGroupAvailablePackageCollections;
    private String managedInstanceGroupId;

    private GetManagedInstanceGroupAvailablePackagesResult() {}
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    public Optional<String> displayNameContains() {
        return Optional.ofNullable(this.displayNameContains);
    }
    /**
     * @return Software source name.
     * 
     */
    public List<String> displayNames() {
        return this.displayNames == null ? List.of() : this.displayNames;
    }
    public List<GetManagedInstanceGroupAvailablePackagesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Flag to return only latest package versions.
     * 
     */
    public Optional<Boolean> isLatest() {
        return Optional.ofNullable(this.isLatest);
    }
    /**
     * @return The list of managed_instance_group_available_package_collection.
     * 
     */
    public List<GetManagedInstanceGroupAvailablePackagesManagedInstanceGroupAvailablePackageCollection> managedInstanceGroupAvailablePackageCollections() {
        return this.managedInstanceGroupAvailablePackageCollections;
    }
    public String managedInstanceGroupId() {
        return this.managedInstanceGroupId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedInstanceGroupAvailablePackagesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable String displayNameContains;
        private @Nullable List<String> displayNames;
        private @Nullable List<GetManagedInstanceGroupAvailablePackagesFilter> filters;
        private String id;
        private @Nullable Boolean isLatest;
        private List<GetManagedInstanceGroupAvailablePackagesManagedInstanceGroupAvailablePackageCollection> managedInstanceGroupAvailablePackageCollections;
        private String managedInstanceGroupId;
        public Builder() {}
        public Builder(GetManagedInstanceGroupAvailablePackagesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayNameContains = defaults.displayNameContains;
    	      this.displayNames = defaults.displayNames;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.isLatest = defaults.isLatest;
    	      this.managedInstanceGroupAvailablePackageCollections = defaults.managedInstanceGroupAvailablePackageCollections;
    	      this.managedInstanceGroupId = defaults.managedInstanceGroupId;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayNameContains(@Nullable String displayNameContains) {
            this.displayNameContains = displayNameContains;
            return this;
        }
        @CustomType.Setter
        public Builder displayNames(@Nullable List<String> displayNames) {
            this.displayNames = displayNames;
            return this;
        }
        public Builder displayNames(String... displayNames) {
            return displayNames(List.of(displayNames));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetManagedInstanceGroupAvailablePackagesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetManagedInstanceGroupAvailablePackagesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder isLatest(@Nullable Boolean isLatest) {
            this.isLatest = isLatest;
            return this;
        }
        @CustomType.Setter
        public Builder managedInstanceGroupAvailablePackageCollections(List<GetManagedInstanceGroupAvailablePackagesManagedInstanceGroupAvailablePackageCollection> managedInstanceGroupAvailablePackageCollections) {
            this.managedInstanceGroupAvailablePackageCollections = Objects.requireNonNull(managedInstanceGroupAvailablePackageCollections);
            return this;
        }
        public Builder managedInstanceGroupAvailablePackageCollections(GetManagedInstanceGroupAvailablePackagesManagedInstanceGroupAvailablePackageCollection... managedInstanceGroupAvailablePackageCollections) {
            return managedInstanceGroupAvailablePackageCollections(List.of(managedInstanceGroupAvailablePackageCollections));
        }
        @CustomType.Setter
        public Builder managedInstanceGroupId(String managedInstanceGroupId) {
            this.managedInstanceGroupId = Objects.requireNonNull(managedInstanceGroupId);
            return this;
        }
        public GetManagedInstanceGroupAvailablePackagesResult build() {
            final var o = new GetManagedInstanceGroupAvailablePackagesResult();
            o.compartmentId = compartmentId;
            o.displayNameContains = displayNameContains;
            o.displayNames = displayNames;
            o.filters = filters;
            o.id = id;
            o.isLatest = isLatest;
            o.managedInstanceGroupAvailablePackageCollections = managedInstanceGroupAvailablePackageCollections;
            o.managedInstanceGroupId = managedInstanceGroupId;
            return o;
        }
    }
}