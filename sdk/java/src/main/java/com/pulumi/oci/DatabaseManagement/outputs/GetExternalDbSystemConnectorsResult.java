// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalDbSystemConnectorsExternalDbSystemConnectorCollection;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalDbSystemConnectorsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetExternalDbSystemConnectorsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return The user-friendly name for the external connector. The name does not have to be unique.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The list of external_db_system_connector_collection.
     * 
     */
    private List<GetExternalDbSystemConnectorsExternalDbSystemConnectorCollection> externalDbSystemConnectorCollections;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the connector is a part of.
     * 
     */
    private @Nullable String externalDbSystemId;
    private @Nullable List<GetExternalDbSystemConnectorsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;

    private GetExternalDbSystemConnectorsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return The user-friendly name for the external connector. The name does not have to be unique.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The list of external_db_system_connector_collection.
     * 
     */
    public List<GetExternalDbSystemConnectorsExternalDbSystemConnectorCollection> externalDbSystemConnectorCollections() {
        return this.externalDbSystemConnectorCollections;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the connector is a part of.
     * 
     */
    public Optional<String> externalDbSystemId() {
        return Optional.ofNullable(this.externalDbSystemId);
    }
    public List<GetExternalDbSystemConnectorsFilter> filters() {
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

    public static Builder builder(GetExternalDbSystemConnectorsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable String displayName;
        private List<GetExternalDbSystemConnectorsExternalDbSystemConnectorCollection> externalDbSystemConnectorCollections;
        private @Nullable String externalDbSystemId;
        private @Nullable List<GetExternalDbSystemConnectorsFilter> filters;
        private String id;
        public Builder() {}
        public Builder(GetExternalDbSystemConnectorsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.externalDbSystemConnectorCollections = defaults.externalDbSystemConnectorCollections;
    	      this.externalDbSystemId = defaults.externalDbSystemId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder externalDbSystemConnectorCollections(List<GetExternalDbSystemConnectorsExternalDbSystemConnectorCollection> externalDbSystemConnectorCollections) {
            this.externalDbSystemConnectorCollections = Objects.requireNonNull(externalDbSystemConnectorCollections);
            return this;
        }
        public Builder externalDbSystemConnectorCollections(GetExternalDbSystemConnectorsExternalDbSystemConnectorCollection... externalDbSystemConnectorCollections) {
            return externalDbSystemConnectorCollections(List.of(externalDbSystemConnectorCollections));
        }
        @CustomType.Setter
        public Builder externalDbSystemId(@Nullable String externalDbSystemId) {
            this.externalDbSystemId = externalDbSystemId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetExternalDbSystemConnectorsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetExternalDbSystemConnectorsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public GetExternalDbSystemConnectorsResult build() {
            final var o = new GetExternalDbSystemConnectorsResult();
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.externalDbSystemConnectorCollections = externalDbSystemConnectorCollections;
            o.externalDbSystemId = externalDbSystemId;
            o.filters = filters;
            o.id = id;
            return o;
        }
    }
}