// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedMySqlDatabaseOutboundReplicationsFilter;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedMySqlDatabaseOutboundReplicationsManagedMySqlDatabaseOutboundReplicationCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetManagedMySqlDatabaseOutboundReplicationsResult {
    private @Nullable List<GetManagedMySqlDatabaseOutboundReplicationsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String managedMySqlDatabaseId;
    /**
     * @return The list of managed_my_sql_database_outbound_replication_collection.
     * 
     */
    private List<GetManagedMySqlDatabaseOutboundReplicationsManagedMySqlDatabaseOutboundReplicationCollection> managedMySqlDatabaseOutboundReplicationCollections;

    private GetManagedMySqlDatabaseOutboundReplicationsResult() {}
    public List<GetManagedMySqlDatabaseOutboundReplicationsFilter> filters() {
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
     * @return The list of managed_my_sql_database_outbound_replication_collection.
     * 
     */
    public List<GetManagedMySqlDatabaseOutboundReplicationsManagedMySqlDatabaseOutboundReplicationCollection> managedMySqlDatabaseOutboundReplicationCollections() {
        return this.managedMySqlDatabaseOutboundReplicationCollections;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedMySqlDatabaseOutboundReplicationsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<GetManagedMySqlDatabaseOutboundReplicationsFilter> filters;
        private String id;
        private String managedMySqlDatabaseId;
        private List<GetManagedMySqlDatabaseOutboundReplicationsManagedMySqlDatabaseOutboundReplicationCollection> managedMySqlDatabaseOutboundReplicationCollections;
        public Builder() {}
        public Builder(GetManagedMySqlDatabaseOutboundReplicationsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.managedMySqlDatabaseId = defaults.managedMySqlDatabaseId;
    	      this.managedMySqlDatabaseOutboundReplicationCollections = defaults.managedMySqlDatabaseOutboundReplicationCollections;
        }

        @CustomType.Setter
        public Builder filters(@Nullable List<GetManagedMySqlDatabaseOutboundReplicationsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetManagedMySqlDatabaseOutboundReplicationsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetManagedMySqlDatabaseOutboundReplicationsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder managedMySqlDatabaseId(String managedMySqlDatabaseId) {
            if (managedMySqlDatabaseId == null) {
              throw new MissingRequiredPropertyException("GetManagedMySqlDatabaseOutboundReplicationsResult", "managedMySqlDatabaseId");
            }
            this.managedMySqlDatabaseId = managedMySqlDatabaseId;
            return this;
        }
        @CustomType.Setter
        public Builder managedMySqlDatabaseOutboundReplicationCollections(List<GetManagedMySqlDatabaseOutboundReplicationsManagedMySqlDatabaseOutboundReplicationCollection> managedMySqlDatabaseOutboundReplicationCollections) {
            if (managedMySqlDatabaseOutboundReplicationCollections == null) {
              throw new MissingRequiredPropertyException("GetManagedMySqlDatabaseOutboundReplicationsResult", "managedMySqlDatabaseOutboundReplicationCollections");
            }
            this.managedMySqlDatabaseOutboundReplicationCollections = managedMySqlDatabaseOutboundReplicationCollections;
            return this;
        }
        public Builder managedMySqlDatabaseOutboundReplicationCollections(GetManagedMySqlDatabaseOutboundReplicationsManagedMySqlDatabaseOutboundReplicationCollection... managedMySqlDatabaseOutboundReplicationCollections) {
            return managedMySqlDatabaseOutboundReplicationCollections(List.of(managedMySqlDatabaseOutboundReplicationCollections));
        }
        public GetManagedMySqlDatabaseOutboundReplicationsResult build() {
            final var _resultValue = new GetManagedMySqlDatabaseOutboundReplicationsResult();
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.managedMySqlDatabaseId = managedMySqlDatabaseId;
            _resultValue.managedMySqlDatabaseOutboundReplicationCollections = managedMySqlDatabaseOutboundReplicationCollections;
            return _resultValue;
        }
    }
}
