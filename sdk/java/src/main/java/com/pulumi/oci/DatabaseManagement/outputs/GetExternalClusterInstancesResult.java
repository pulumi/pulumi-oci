// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalClusterInstancesExternalClusterInstanceCollection;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalClusterInstancesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetExternalClusterInstancesResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return The user-friendly name for the cluster instance. The name does not have to be unique.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster that the cluster instance belongs to.
     * 
     */
    private @Nullable String externalClusterId;
    /**
     * @return The list of external_cluster_instance_collection.
     * 
     */
    private List<GetExternalClusterInstancesExternalClusterInstanceCollection> externalClusterInstanceCollections;
    private @Nullable List<GetExternalClusterInstancesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;

    private GetExternalClusterInstancesResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return The user-friendly name for the cluster instance. The name does not have to be unique.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external cluster that the cluster instance belongs to.
     * 
     */
    public Optional<String> externalClusterId() {
        return Optional.ofNullable(this.externalClusterId);
    }
    /**
     * @return The list of external_cluster_instance_collection.
     * 
     */
    public List<GetExternalClusterInstancesExternalClusterInstanceCollection> externalClusterInstanceCollections() {
        return this.externalClusterInstanceCollections;
    }
    public List<GetExternalClusterInstancesFilter> filters() {
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

    public static Builder builder(GetExternalClusterInstancesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable String displayName;
        private @Nullable String externalClusterId;
        private List<GetExternalClusterInstancesExternalClusterInstanceCollection> externalClusterInstanceCollections;
        private @Nullable List<GetExternalClusterInstancesFilter> filters;
        private String id;
        public Builder() {}
        public Builder(GetExternalClusterInstancesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.externalClusterId = defaults.externalClusterId;
    	      this.externalClusterInstanceCollections = defaults.externalClusterInstanceCollections;
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
        public Builder externalClusterId(@Nullable String externalClusterId) {
            this.externalClusterId = externalClusterId;
            return this;
        }
        @CustomType.Setter
        public Builder externalClusterInstanceCollections(List<GetExternalClusterInstancesExternalClusterInstanceCollection> externalClusterInstanceCollections) {
            this.externalClusterInstanceCollections = Objects.requireNonNull(externalClusterInstanceCollections);
            return this;
        }
        public Builder externalClusterInstanceCollections(GetExternalClusterInstancesExternalClusterInstanceCollection... externalClusterInstanceCollections) {
            return externalClusterInstanceCollections(List.of(externalClusterInstanceCollections));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetExternalClusterInstancesFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetExternalClusterInstancesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public GetExternalClusterInstancesResult build() {
            final var o = new GetExternalClusterInstancesResult();
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.externalClusterId = externalClusterId;
            o.externalClusterInstanceCollections = externalClusterInstanceCollections;
            o.filters = filters;
            o.id = id;
            return o;
        }
    }
}