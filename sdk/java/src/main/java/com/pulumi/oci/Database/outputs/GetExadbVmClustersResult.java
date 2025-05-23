// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetExadbVmClustersExadbVmCluster;
import com.pulumi.oci.Database.outputs.GetExadbVmClustersFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetExadbVmClustersResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group of the Exadata Infrastructure.
     * 
     */
    private @Nullable String clusterPlacementGroupId;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The user-friendly name for the Exadata VM cluster on Exascale Infrastructure. The name does not need to be unique.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The list of exadb_vm_clusters.
     * 
     */
    private List<GetExadbVmClustersExadbVmCluster> exadbVmClusters;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata Database Storage Vault.
     * 
     */
    private @Nullable String exascaleDbStorageVaultId;
    private @Nullable List<GetExadbVmClustersFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The current state of the Exadata VM cluster on Exascale Infrastructure.
     * 
     */
    private @Nullable String state;

    private GetExadbVmClustersResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cluster placement group of the Exadata Infrastructure.
     * 
     */
    public Optional<String> clusterPlacementGroupId() {
        return Optional.ofNullable(this.clusterPlacementGroupId);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The user-friendly name for the Exadata VM cluster on Exascale Infrastructure. The name does not need to be unique.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The list of exadb_vm_clusters.
     * 
     */
    public List<GetExadbVmClustersExadbVmCluster> exadbVmClusters() {
        return this.exadbVmClusters;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata Database Storage Vault.
     * 
     */
    public Optional<String> exascaleDbStorageVaultId() {
        return Optional.ofNullable(this.exascaleDbStorageVaultId);
    }
    public List<GetExadbVmClustersFilter> filters() {
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
     * @return The current state of the Exadata VM cluster on Exascale Infrastructure.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExadbVmClustersResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String clusterPlacementGroupId;
        private String compartmentId;
        private @Nullable String displayName;
        private List<GetExadbVmClustersExadbVmCluster> exadbVmClusters;
        private @Nullable String exascaleDbStorageVaultId;
        private @Nullable List<GetExadbVmClustersFilter> filters;
        private String id;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetExadbVmClustersResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.clusterPlacementGroupId = defaults.clusterPlacementGroupId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.exadbVmClusters = defaults.exadbVmClusters;
    	      this.exascaleDbStorageVaultId = defaults.exascaleDbStorageVaultId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder clusterPlacementGroupId(@Nullable String clusterPlacementGroupId) {

            this.clusterPlacementGroupId = clusterPlacementGroupId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClustersResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder exadbVmClusters(List<GetExadbVmClustersExadbVmCluster> exadbVmClusters) {
            if (exadbVmClusters == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClustersResult", "exadbVmClusters");
            }
            this.exadbVmClusters = exadbVmClusters;
            return this;
        }
        public Builder exadbVmClusters(GetExadbVmClustersExadbVmCluster... exadbVmClusters) {
            return exadbVmClusters(List.of(exadbVmClusters));
        }
        @CustomType.Setter
        public Builder exascaleDbStorageVaultId(@Nullable String exascaleDbStorageVaultId) {

            this.exascaleDbStorageVaultId = exascaleDbStorageVaultId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetExadbVmClustersFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetExadbVmClustersFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetExadbVmClustersResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetExadbVmClustersResult build() {
            final var _resultValue = new GetExadbVmClustersResult();
            _resultValue.clusterPlacementGroupId = clusterPlacementGroupId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.exadbVmClusters = exadbVmClusters;
            _resultValue.exascaleDbStorageVaultId = exascaleDbStorageVaultId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
