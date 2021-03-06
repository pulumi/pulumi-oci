// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabasesFilter;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabasesManagedDatabaseCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetManagedDatabasesResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
     * 
     */
    private final String compartmentId;
    /**
     * @return The infrastructure used to deploy the Oracle Database.
     * 
     */
    private final @Nullable String deploymentType;
    private final @Nullable List<GetManagedDatabasesFilter> filters;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database Group.
     * 
     */
    private final @Nullable String id;
    /**
     * @return The list of managed_database_collection.
     * 
     */
    private final List<GetManagedDatabasesManagedDatabaseCollection> managedDatabaseCollections;
    /**
     * @return The management option used when enabling Database Management.
     * 
     */
    private final @Nullable String managementOption;
    /**
     * @return The name of the Managed Database.
     * 
     */
    private final @Nullable String name;

    @CustomType.Constructor
    private GetManagedDatabasesResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("deploymentType") @Nullable String deploymentType,
        @CustomType.Parameter("filters") @Nullable List<GetManagedDatabasesFilter> filters,
        @CustomType.Parameter("id") @Nullable String id,
        @CustomType.Parameter("managedDatabaseCollections") List<GetManagedDatabasesManagedDatabaseCollection> managedDatabaseCollections,
        @CustomType.Parameter("managementOption") @Nullable String managementOption,
        @CustomType.Parameter("name") @Nullable String name) {
        this.compartmentId = compartmentId;
        this.deploymentType = deploymentType;
        this.filters = filters;
        this.id = id;
        this.managedDatabaseCollections = managedDatabaseCollections;
        this.managementOption = managementOption;
        this.name = name;
    }

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the Managed Database Group resides.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The infrastructure used to deploy the Oracle Database.
     * 
     */
    public Optional<String> deploymentType() {
        return Optional.ofNullable(this.deploymentType);
    }
    public List<GetManagedDatabasesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database Group.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The list of managed_database_collection.
     * 
     */
    public List<GetManagedDatabasesManagedDatabaseCollection> managedDatabaseCollections() {
        return this.managedDatabaseCollections;
    }
    /**
     * @return The management option used when enabling Database Management.
     * 
     */
    public Optional<String> managementOption() {
        return Optional.ofNullable(this.managementOption);
    }
    /**
     * @return The name of the Managed Database.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabasesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable String deploymentType;
        private @Nullable List<GetManagedDatabasesFilter> filters;
        private @Nullable String id;
        private List<GetManagedDatabasesManagedDatabaseCollection> managedDatabaseCollections;
        private @Nullable String managementOption;
        private @Nullable String name;

        public Builder() {
    	      // Empty
        }

        public Builder(GetManagedDatabasesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.deploymentType = defaults.deploymentType;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.managedDatabaseCollections = defaults.managedDatabaseCollections;
    	      this.managementOption = defaults.managementOption;
    	      this.name = defaults.name;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder deploymentType(@Nullable String deploymentType) {
            this.deploymentType = deploymentType;
            return this;
        }
        public Builder filters(@Nullable List<GetManagedDatabasesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetManagedDatabasesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        public Builder managedDatabaseCollections(List<GetManagedDatabasesManagedDatabaseCollection> managedDatabaseCollections) {
            this.managedDatabaseCollections = Objects.requireNonNull(managedDatabaseCollections);
            return this;
        }
        public Builder managedDatabaseCollections(GetManagedDatabasesManagedDatabaseCollection... managedDatabaseCollections) {
            return managedDatabaseCollections(List.of(managedDatabaseCollections));
        }
        public Builder managementOption(@Nullable String managementOption) {
            this.managementOption = managementOption;
            return this;
        }
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }        public GetManagedDatabasesResult build() {
            return new GetManagedDatabasesResult(compartmentId, deploymentType, filters, id, managedDatabaseCollections, managementOption, name);
        }
    }
}
