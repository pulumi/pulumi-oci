// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollection;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalDbSystemDiscoveriesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetExternalDbSystemDiscoveriesResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The user-friendly name for the DB system. The name does not have to be unique.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The list of external_db_system_discovery_collection.
     * 
     */
    private List<GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollection> externalDbSystemDiscoveryCollections;
    private @Nullable List<GetExternalDbSystemDiscoveriesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;

    private GetExternalDbSystemDiscoveriesResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The user-friendly name for the DB system. The name does not have to be unique.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The list of external_db_system_discovery_collection.
     * 
     */
    public List<GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollection> externalDbSystemDiscoveryCollections() {
        return this.externalDbSystemDiscoveryCollections;
    }
    public List<GetExternalDbSystemDiscoveriesFilter> filters() {
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

    public static Builder builder(GetExternalDbSystemDiscoveriesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private List<GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollection> externalDbSystemDiscoveryCollections;
        private @Nullable List<GetExternalDbSystemDiscoveriesFilter> filters;
        private String id;
        public Builder() {}
        public Builder(GetExternalDbSystemDiscoveriesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.externalDbSystemDiscoveryCollections = defaults.externalDbSystemDiscoveryCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
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
        public Builder externalDbSystemDiscoveryCollections(List<GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollection> externalDbSystemDiscoveryCollections) {
            this.externalDbSystemDiscoveryCollections = Objects.requireNonNull(externalDbSystemDiscoveryCollections);
            return this;
        }
        public Builder externalDbSystemDiscoveryCollections(GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollection... externalDbSystemDiscoveryCollections) {
            return externalDbSystemDiscoveryCollections(List.of(externalDbSystemDiscoveryCollections));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetExternalDbSystemDiscoveriesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetExternalDbSystemDiscoveriesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public GetExternalDbSystemDiscoveriesResult build() {
            final var o = new GetExternalDbSystemDiscoveriesResult();
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.externalDbSystemDiscoveryCollections = externalDbSystemDiscoveryCollections;
            o.filters = filters;
            o.id = id;
            return o;
        }
    }
}