// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetCloudVmClustersCloudVmCluster;
import com.pulumi.oci.Database.outputs.GetCloudVmClustersFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetCloudVmClustersResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure.
     * 
     */
    private @Nullable String cloudExadataInfrastructureId;
    /**
     * @return The list of cloud_vm_clusters.
     * 
     */
    private List<GetCloudVmClustersCloudVmCluster> cloudVmClusters;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The user-friendly name for the cloud VM cluster. The name does not need to be unique.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetCloudVmClustersFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The current state of the cloud VM cluster.
     * 
     */
    private @Nullable String state;
    /**
     * @return The vmcluster type for the VM cluster/Cloud VM cluster.
     * 
     */
    private @Nullable String vmClusterType;

    private GetCloudVmClustersResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure.
     * 
     */
    public Optional<String> cloudExadataInfrastructureId() {
        return Optional.ofNullable(this.cloudExadataInfrastructureId);
    }
    /**
     * @return The list of cloud_vm_clusters.
     * 
     */
    public List<GetCloudVmClustersCloudVmCluster> cloudVmClusters() {
        return this.cloudVmClusters;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The user-friendly name for the cloud VM cluster. The name does not need to be unique.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetCloudVmClustersFilter> filters() {
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
     * @return The current state of the cloud VM cluster.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The vmcluster type for the VM cluster/Cloud VM cluster.
     * 
     */
    public Optional<String> vmClusterType() {
        return Optional.ofNullable(this.vmClusterType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCloudVmClustersResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String cloudExadataInfrastructureId;
        private List<GetCloudVmClustersCloudVmCluster> cloudVmClusters;
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetCloudVmClustersFilter> filters;
        private String id;
        private @Nullable String state;
        private @Nullable String vmClusterType;
        public Builder() {}
        public Builder(GetCloudVmClustersResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.cloudExadataInfrastructureId = defaults.cloudExadataInfrastructureId;
    	      this.cloudVmClusters = defaults.cloudVmClusters;
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.vmClusterType = defaults.vmClusterType;
        }

        @CustomType.Setter
        public Builder cloudExadataInfrastructureId(@Nullable String cloudExadataInfrastructureId) {

            this.cloudExadataInfrastructureId = cloudExadataInfrastructureId;
            return this;
        }
        @CustomType.Setter
        public Builder cloudVmClusters(List<GetCloudVmClustersCloudVmCluster> cloudVmClusters) {
            if (cloudVmClusters == null) {
              throw new MissingRequiredPropertyException("GetCloudVmClustersResult", "cloudVmClusters");
            }
            this.cloudVmClusters = cloudVmClusters;
            return this;
        }
        public Builder cloudVmClusters(GetCloudVmClustersCloudVmCluster... cloudVmClusters) {
            return cloudVmClusters(List.of(cloudVmClusters));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetCloudVmClustersResult", "compartmentId");
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
        public Builder filters(@Nullable List<GetCloudVmClustersFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetCloudVmClustersFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetCloudVmClustersResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder vmClusterType(@Nullable String vmClusterType) {

            this.vmClusterType = vmClusterType;
            return this;
        }
        public GetCloudVmClustersResult build() {
            final var _resultValue = new GetCloudVmClustersResult();
            _resultValue.cloudExadataInfrastructureId = cloudExadataInfrastructureId;
            _resultValue.cloudVmClusters = cloudVmClusters;
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.state = state;
            _resultValue.vmClusterType = vmClusterType;
            return _resultValue;
        }
    }
}
