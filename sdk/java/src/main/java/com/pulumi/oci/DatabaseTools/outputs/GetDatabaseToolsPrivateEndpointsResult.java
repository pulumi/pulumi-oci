// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseTools.outputs.GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollection;
import com.pulumi.oci.DatabaseTools.outputs.GetDatabaseToolsPrivateEndpointsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDatabaseToolsPrivateEndpointsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools private endpoint.
     * 
     */
    private String compartmentId;
    /**
     * @return The list of database_tools_private_endpoint_collection.
     * 
     */
    private List<GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollection> databaseToolsPrivateEndpointCollections;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools Endpoint Service.
     * 
     */
    private @Nullable String endpointServiceId;
    private @Nullable List<GetDatabaseToolsPrivateEndpointsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The current state of the Database Tools private endpoint.
     * 
     */
    private @Nullable String state;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.
     * 
     */
    private @Nullable String subnetId;

    private GetDatabaseToolsPrivateEndpointsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the Database Tools private endpoint.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of database_tools_private_endpoint_collection.
     * 
     */
    public List<GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollection> databaseToolsPrivateEndpointCollections() {
        return this.databaseToolsPrivateEndpointCollections;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools Endpoint Service.
     * 
     */
    public Optional<String> endpointServiceId() {
        return Optional.ofNullable(this.endpointServiceId);
    }
    public List<GetDatabaseToolsPrivateEndpointsFilter> filters() {
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
     * @return The current state of the Database Tools private endpoint.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet that the private endpoint belongs to.
     * 
     */
    public Optional<String> subnetId() {
        return Optional.ofNullable(this.subnetId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDatabaseToolsPrivateEndpointsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollection> databaseToolsPrivateEndpointCollections;
        private @Nullable String displayName;
        private @Nullable String endpointServiceId;
        private @Nullable List<GetDatabaseToolsPrivateEndpointsFilter> filters;
        private String id;
        private @Nullable String state;
        private @Nullable String subnetId;
        public Builder() {}
        public Builder(GetDatabaseToolsPrivateEndpointsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.databaseToolsPrivateEndpointCollections = defaults.databaseToolsPrivateEndpointCollections;
    	      this.displayName = defaults.displayName;
    	      this.endpointServiceId = defaults.endpointServiceId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.subnetId = defaults.subnetId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder databaseToolsPrivateEndpointCollections(List<GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollection> databaseToolsPrivateEndpointCollections) {
            this.databaseToolsPrivateEndpointCollections = Objects.requireNonNull(databaseToolsPrivateEndpointCollections);
            return this;
        }
        public Builder databaseToolsPrivateEndpointCollections(GetDatabaseToolsPrivateEndpointsDatabaseToolsPrivateEndpointCollection... databaseToolsPrivateEndpointCollections) {
            return databaseToolsPrivateEndpointCollections(List.of(databaseToolsPrivateEndpointCollections));
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder endpointServiceId(@Nullable String endpointServiceId) {
            this.endpointServiceId = endpointServiceId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetDatabaseToolsPrivateEndpointsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDatabaseToolsPrivateEndpointsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder subnetId(@Nullable String subnetId) {
            this.subnetId = subnetId;
            return this;
        }
        public GetDatabaseToolsPrivateEndpointsResult build() {
            final var o = new GetDatabaseToolsPrivateEndpointsResult();
            o.compartmentId = compartmentId;
            o.databaseToolsPrivateEndpointCollections = databaseToolsPrivateEndpointCollections;
            o.displayName = displayName;
            o.endpointServiceId = endpointServiceId;
            o.filters = filters;
            o.id = id;
            o.state = state;
            o.subnetId = subnetId;
            return o;
        }
    }
}