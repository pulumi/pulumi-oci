// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.OsManagement.outputs.GetManagedInstancesFilter;
import com.pulumi.oci.OsManagement.outputs.GetManagedInstancesManagedInstance;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetManagedInstancesResult {
    /**
     * @return OCID for the Compartment
     * 
     */
    private String compartmentId;
    /**
     * @return User friendly name
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetManagedInstancesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of managed_instances.
     * 
     */
    private List<GetManagedInstancesManagedInstance> managedInstances;
    /**
     * @return The Operating System type of the managed instance.
     * 
     */
    private @Nullable String osFamily;

    private GetManagedInstancesResult() {}
    /**
     * @return OCID for the Compartment
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return User friendly name
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetManagedInstancesFilter> filters() {
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
     * @return The list of managed_instances.
     * 
     */
    public List<GetManagedInstancesManagedInstance> managedInstances() {
        return this.managedInstances;
    }
    /**
     * @return The Operating System type of the managed instance.
     * 
     */
    public Optional<String> osFamily() {
        return Optional.ofNullable(this.osFamily);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedInstancesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetManagedInstancesFilter> filters;
        private String id;
        private List<GetManagedInstancesManagedInstance> managedInstances;
        private @Nullable String osFamily;
        public Builder() {}
        public Builder(GetManagedInstancesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.managedInstances = defaults.managedInstances;
    	      this.osFamily = defaults.osFamily;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetManagedInstancesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetManagedInstancesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder managedInstances(List<GetManagedInstancesManagedInstance> managedInstances) {
            this.managedInstances = Objects.requireNonNull(managedInstances);
            return this;
        }
        public Builder managedInstances(GetManagedInstancesManagedInstance... managedInstances) {
            return managedInstances(List.of(managedInstances));
        }
        @CustomType.Setter
        public Builder osFamily(@Nullable String osFamily) {
            this.osFamily = osFamily;
            return this;
        }
        public GetManagedInstancesResult build() {
            final var o = new GetManagedInstancesResult();
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.managedInstances = managedInstances;
            o.osFamily = osFamily;
            return o;
        }
    }
}