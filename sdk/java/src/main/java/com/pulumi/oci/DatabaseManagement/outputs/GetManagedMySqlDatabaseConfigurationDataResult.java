// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedMySqlDatabaseConfigurationDataFilter;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedMySqlDatabaseConfigurationDataMySqlConfigurationDataCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetManagedMySqlDatabaseConfigurationDataResult {
    private @Nullable List<GetManagedMySqlDatabaseConfigurationDataFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String managedMySqlDatabaseId;
    /**
     * @return The list of my_sql_configuration_data_collection.
     * 
     */
    private List<GetManagedMySqlDatabaseConfigurationDataMySqlConfigurationDataCollection> mySqlConfigurationDataCollections;

    private GetManagedMySqlDatabaseConfigurationDataResult() {}
    public List<GetManagedMySqlDatabaseConfigurationDataFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String managedMySqlDatabaseId() {
        return this.managedMySqlDatabaseId;
    }
    /**
     * @return The list of my_sql_configuration_data_collection.
     * 
     */
    public List<GetManagedMySqlDatabaseConfigurationDataMySqlConfigurationDataCollection> mySqlConfigurationDataCollections() {
        return this.mySqlConfigurationDataCollections;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedMySqlDatabaseConfigurationDataResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetManagedMySqlDatabaseConfigurationDataFilter> filters;
        private String id;
        private String managedMySqlDatabaseId;
        private List<GetManagedMySqlDatabaseConfigurationDataMySqlConfigurationDataCollection> mySqlConfigurationDataCollections;
        public Builder() {}
        public Builder(GetManagedMySqlDatabaseConfigurationDataResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.managedMySqlDatabaseId = defaults.managedMySqlDatabaseId;
    	      this.mySqlConfigurationDataCollections = defaults.mySqlConfigurationDataCollections;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetManagedMySqlDatabaseConfigurationDataFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetManagedMySqlDatabaseConfigurationDataFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder managedMySqlDatabaseId(String managedMySqlDatabaseId) {
            this.managedMySqlDatabaseId = Objects.requireNonNull(managedMySqlDatabaseId);
            return this;
        }
        @CustomType.Setter
        public Builder mySqlConfigurationDataCollections(List<GetManagedMySqlDatabaseConfigurationDataMySqlConfigurationDataCollection> mySqlConfigurationDataCollections) {
            this.mySqlConfigurationDataCollections = Objects.requireNonNull(mySqlConfigurationDataCollections);
            return this;
        }
        public Builder mySqlConfigurationDataCollections(GetManagedMySqlDatabaseConfigurationDataMySqlConfigurationDataCollection... mySqlConfigurationDataCollections) {
            return mySqlConfigurationDataCollections(List.of(mySqlConfigurationDataCollections));
        }
        public GetManagedMySqlDatabaseConfigurationDataResult build() {
            final var o = new GetManagedMySqlDatabaseConfigurationDataResult();
            o.filters = filters;
            o.id = id;
            o.managedMySqlDatabaseId = managedMySqlDatabaseId;
            o.mySqlConfigurationDataCollections = mySqlConfigurationDataCollections;
            return o;
        }
    }
}