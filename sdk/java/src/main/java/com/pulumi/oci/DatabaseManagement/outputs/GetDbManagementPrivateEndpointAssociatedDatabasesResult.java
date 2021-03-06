// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetDbManagementPrivateEndpointAssociatedDatabasesAssociatedDatabaseCollection;
import com.pulumi.oci.DatabaseManagement.outputs.GetDbManagementPrivateEndpointAssociatedDatabasesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetDbManagementPrivateEndpointAssociatedDatabasesResult {
    /**
     * @return The list of associated_database_collection.
     * 
     */
    private final List<GetDbManagementPrivateEndpointAssociatedDatabasesAssociatedDatabaseCollection> associatedDatabaseCollections;
    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
     * 
     */
    private final String compartmentId;
    private final String dbManagementPrivateEndpointId;
    private final @Nullable List<GetDbManagementPrivateEndpointAssociatedDatabasesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;

    @CustomType.Constructor
    private GetDbManagementPrivateEndpointAssociatedDatabasesResult(
        @CustomType.Parameter("associatedDatabaseCollections") List<GetDbManagementPrivateEndpointAssociatedDatabasesAssociatedDatabaseCollection> associatedDatabaseCollections,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("dbManagementPrivateEndpointId") String dbManagementPrivateEndpointId,
        @CustomType.Parameter("filters") @Nullable List<GetDbManagementPrivateEndpointAssociatedDatabasesFilter> filters,
        @CustomType.Parameter("id") String id) {
        this.associatedDatabaseCollections = associatedDatabaseCollections;
        this.compartmentId = compartmentId;
        this.dbManagementPrivateEndpointId = dbManagementPrivateEndpointId;
        this.filters = filters;
        this.id = id;
    }

    /**
     * @return The list of associated_database_collection.
     * 
     */
    public List<GetDbManagementPrivateEndpointAssociatedDatabasesAssociatedDatabaseCollection> associatedDatabaseCollections() {
        return this.associatedDatabaseCollections;
    }
    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the database.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public String dbManagementPrivateEndpointId() {
        return this.dbManagementPrivateEndpointId;
    }
    public List<GetDbManagementPrivateEndpointAssociatedDatabasesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDbManagementPrivateEndpointAssociatedDatabasesResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetDbManagementPrivateEndpointAssociatedDatabasesAssociatedDatabaseCollection> associatedDatabaseCollections;
        private String compartmentId;
        private String dbManagementPrivateEndpointId;
        private @Nullable List<GetDbManagementPrivateEndpointAssociatedDatabasesFilter> filters;
        private String id;

        public Builder() {
    	      // Empty
        }

        public Builder(GetDbManagementPrivateEndpointAssociatedDatabasesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.associatedDatabaseCollections = defaults.associatedDatabaseCollections;
    	      this.compartmentId = defaults.compartmentId;
    	      this.dbManagementPrivateEndpointId = defaults.dbManagementPrivateEndpointId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
        }

        public Builder associatedDatabaseCollections(List<GetDbManagementPrivateEndpointAssociatedDatabasesAssociatedDatabaseCollection> associatedDatabaseCollections) {
            this.associatedDatabaseCollections = Objects.requireNonNull(associatedDatabaseCollections);
            return this;
        }
        public Builder associatedDatabaseCollections(GetDbManagementPrivateEndpointAssociatedDatabasesAssociatedDatabaseCollection... associatedDatabaseCollections) {
            return associatedDatabaseCollections(List.of(associatedDatabaseCollections));
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder dbManagementPrivateEndpointId(String dbManagementPrivateEndpointId) {
            this.dbManagementPrivateEndpointId = Objects.requireNonNull(dbManagementPrivateEndpointId);
            return this;
        }
        public Builder filters(@Nullable List<GetDbManagementPrivateEndpointAssociatedDatabasesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDbManagementPrivateEndpointAssociatedDatabasesFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }        public GetDbManagementPrivateEndpointAssociatedDatabasesResult build() {
            return new GetDbManagementPrivateEndpointAssociatedDatabasesResult(associatedDatabaseCollections, compartmentId, dbManagementPrivateEndpointId, filters, id);
        }
    }
}
