// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.outputs.GetManagedInstanceAvailablePackagesAvailablePackageCollection;
import com.pulumi.oci.OsManagementHub.outputs.GetManagedInstanceAvailablePackagesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetManagedInstanceAvailablePackagesResult {
    /**
     * @return The list of available_package_collection.
     * 
     */
    private List<GetManagedInstanceAvailablePackagesAvailablePackageCollection> availablePackageCollections;
    private @Nullable String compartmentId;
    private @Nullable String displayNameContains;
    /**
     * @return Software source name.
     * 
     */
    private @Nullable List<String> displayNames;
    private @Nullable List<GetManagedInstanceAvailablePackagesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String managedInstanceId;

    private GetManagedInstanceAvailablePackagesResult() {}
    /**
     * @return The list of available_package_collection.
     * 
     */
    public List<GetManagedInstanceAvailablePackagesAvailablePackageCollection> availablePackageCollections() {
        return this.availablePackageCollections;
    }
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
    public List<GetManagedInstanceAvailablePackagesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String managedInstanceId() {
        return this.managedInstanceId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedInstanceAvailablePackagesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetManagedInstanceAvailablePackagesAvailablePackageCollection> availablePackageCollections;
        private @Nullable String compartmentId;
        private @Nullable String displayNameContains;
        private @Nullable List<String> displayNames;
        private @Nullable List<GetManagedInstanceAvailablePackagesFilter> filters;
        private String id;
        private String managedInstanceId;
        public Builder() {}
        public Builder(GetManagedInstanceAvailablePackagesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availablePackageCollections = defaults.availablePackageCollections;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayNameContains = defaults.displayNameContains;
    	      this.displayNames = defaults.displayNames;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.managedInstanceId = defaults.managedInstanceId;
        }

        @CustomType.Setter
        public Builder availablePackageCollections(List<GetManagedInstanceAvailablePackagesAvailablePackageCollection> availablePackageCollections) {
            if (availablePackageCollections == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceAvailablePackagesResult", "availablePackageCollections");
            }
            this.availablePackageCollections = availablePackageCollections;
            return this;
        }
        public Builder availablePackageCollections(GetManagedInstanceAvailablePackagesAvailablePackageCollection... availablePackageCollections) {
            return availablePackageCollections(List.of(availablePackageCollections));
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
        public Builder filters(@Nullable List<GetManagedInstanceAvailablePackagesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetManagedInstanceAvailablePackagesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceAvailablePackagesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder managedInstanceId(String managedInstanceId) {
            if (managedInstanceId == null) {
              throw new MissingRequiredPropertyException("GetManagedInstanceAvailablePackagesResult", "managedInstanceId");
            }
            this.managedInstanceId = managedInstanceId;
            return this;
        }
        public GetManagedInstanceAvailablePackagesResult build() {
            final var _resultValue = new GetManagedInstanceAvailablePackagesResult();
            _resultValue.availablePackageCollections = availablePackageCollections;
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayNameContains = displayNameContains;
            _resultValue.displayNames = displayNames;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.managedInstanceId = managedInstanceId;
            return _resultValue;
        }
    }
}
