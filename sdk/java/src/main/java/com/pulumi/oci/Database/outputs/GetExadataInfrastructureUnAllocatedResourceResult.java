// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetExadataInfrastructureUnAllocatedResourceAutonomousVmCluster;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetExadataInfrastructureUnAllocatedResourceResult {
    /**
     * @return The list of Autonomous VM Clusters on the Infra and their associated unallocated resources details
     * 
     */
    private List<GetExadataInfrastructureUnAllocatedResourceAutonomousVmCluster> autonomousVmClusters;
    private @Nullable List<String> dbServers;
    /**
     * @return The user-friendly name for the Exadata Cloud@Customer infrastructure. The name does not need to be unique.
     * 
     */
    private String displayName;
    private String exadataInfrastructureId;
    /**
     * @return Total unallocated exadata storage in the infrastructure in TBs.
     * 
     */
    private Double exadataStorageInTbs;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The minimum amount of un allocated storage that is available across all nodes in the infrastructure.
     * 
     */
    private Integer localStorageInGbs;
    /**
     * @return The minimum amount of un allocated memory that is available across all nodes in the infrastructure.
     * 
     */
    private Integer memoryInGbs;
    /**
     * @return The minimum amount of un allocated ocpus that is available across all nodes in the infrastructure.
     * 
     */
    private Integer ocpus;

    private GetExadataInfrastructureUnAllocatedResourceResult() {}
    /**
     * @return The list of Autonomous VM Clusters on the Infra and their associated unallocated resources details
     * 
     */
    public List<GetExadataInfrastructureUnAllocatedResourceAutonomousVmCluster> autonomousVmClusters() {
        return this.autonomousVmClusters;
    }
    public List<String> dbServers() {
        return this.dbServers == null ? List.of() : this.dbServers;
    }
    /**
     * @return The user-friendly name for the Exadata Cloud@Customer infrastructure. The name does not need to be unique.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    public String exadataInfrastructureId() {
        return this.exadataInfrastructureId;
    }
    /**
     * @return Total unallocated exadata storage in the infrastructure in TBs.
     * 
     */
    public Double exadataStorageInTbs() {
        return this.exadataStorageInTbs;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The minimum amount of un allocated storage that is available across all nodes in the infrastructure.
     * 
     */
    public Integer localStorageInGbs() {
        return this.localStorageInGbs;
    }
    /**
     * @return The minimum amount of un allocated memory that is available across all nodes in the infrastructure.
     * 
     */
    public Integer memoryInGbs() {
        return this.memoryInGbs;
    }
    /**
     * @return The minimum amount of un allocated ocpus that is available across all nodes in the infrastructure.
     * 
     */
    public Integer ocpus() {
        return this.ocpus;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExadataInfrastructureUnAllocatedResourceResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetExadataInfrastructureUnAllocatedResourceAutonomousVmCluster> autonomousVmClusters;
        private @Nullable List<String> dbServers;
        private String displayName;
        private String exadataInfrastructureId;
        private Double exadataStorageInTbs;
        private String id;
        private Integer localStorageInGbs;
        private Integer memoryInGbs;
        private Integer ocpus;
        public Builder() {}
        public Builder(GetExadataInfrastructureUnAllocatedResourceResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.autonomousVmClusters = defaults.autonomousVmClusters;
    	      this.dbServers = defaults.dbServers;
    	      this.displayName = defaults.displayName;
    	      this.exadataInfrastructureId = defaults.exadataInfrastructureId;
    	      this.exadataStorageInTbs = defaults.exadataStorageInTbs;
    	      this.id = defaults.id;
    	      this.localStorageInGbs = defaults.localStorageInGbs;
    	      this.memoryInGbs = defaults.memoryInGbs;
    	      this.ocpus = defaults.ocpus;
        }

        @CustomType.Setter
        public Builder autonomousVmClusters(List<GetExadataInfrastructureUnAllocatedResourceAutonomousVmCluster> autonomousVmClusters) {
            this.autonomousVmClusters = Objects.requireNonNull(autonomousVmClusters);
            return this;
        }
        public Builder autonomousVmClusters(GetExadataInfrastructureUnAllocatedResourceAutonomousVmCluster... autonomousVmClusters) {
            return autonomousVmClusters(List.of(autonomousVmClusters));
        }
        @CustomType.Setter
        public Builder dbServers(@Nullable List<String> dbServers) {
            this.dbServers = dbServers;
            return this;
        }
        public Builder dbServers(String... dbServers) {
            return dbServers(List.of(dbServers));
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder exadataInfrastructureId(String exadataInfrastructureId) {
            this.exadataInfrastructureId = Objects.requireNonNull(exadataInfrastructureId);
            return this;
        }
        @CustomType.Setter
        public Builder exadataStorageInTbs(Double exadataStorageInTbs) {
            this.exadataStorageInTbs = Objects.requireNonNull(exadataStorageInTbs);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder localStorageInGbs(Integer localStorageInGbs) {
            this.localStorageInGbs = Objects.requireNonNull(localStorageInGbs);
            return this;
        }
        @CustomType.Setter
        public Builder memoryInGbs(Integer memoryInGbs) {
            this.memoryInGbs = Objects.requireNonNull(memoryInGbs);
            return this;
        }
        @CustomType.Setter
        public Builder ocpus(Integer ocpus) {
            this.ocpus = Objects.requireNonNull(ocpus);
            return this;
        }
        public GetExadataInfrastructureUnAllocatedResourceResult build() {
            final var o = new GetExadataInfrastructureUnAllocatedResourceResult();
            o.autonomousVmClusters = autonomousVmClusters;
            o.dbServers = dbServers;
            o.displayName = displayName;
            o.exadataInfrastructureId = exadataInfrastructureId;
            o.exadataStorageInTbs = exadataStorageInTbs;
            o.id = id;
            o.localStorageInGbs = localStorageInGbs;
            o.memoryInGbs = memoryInGbs;
            o.ocpus = ocpus;
            return o;
        }
    }
}