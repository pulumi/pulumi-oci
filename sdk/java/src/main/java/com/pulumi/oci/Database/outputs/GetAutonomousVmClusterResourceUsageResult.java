// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetAutonomousVmClusterResourceUsageAutonomousVmResourceUsage;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAutonomousVmClusterResourceUsageResult {
    /**
     * @return The data disk group size allocated for Autonomous Databases, in TBs.
     * 
     */
    private Double autonomousDataStorageSizeInTbs;
    private String autonomousVmClusterId;
    /**
     * @return List of autonomous vm cluster resource usages.
     * 
     */
    private List<GetAutonomousVmClusterResourceUsageAutonomousVmResourceUsage> autonomousVmResourceUsages;
    /**
     * @return The data disk group size available for Autonomous Databases, in TBs.
     * 
     */
    private Double availableAutonomousDataStorageSizeInTbs;
    /**
     * @return The number of CPU cores available.
     * 
     */
    private Double availableCpus;
    /**
     * @return The local node storage allocated in GBs.
     * 
     */
    private Integer dbNodeStorageSizeInGbs;
    /**
     * @return The user-friendly name for the Autonomous VM cluster. The name does not need to be unique.
     * 
     */
    private String displayName;
    /**
     * @return Total exadata storage allocated for the Autonomous VM Cluster. DATA + RECOVERY + SPARSE + any overhead in TBs.
     * 
     */
    private Double exadataStorageInTbs;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return If true, database backup on local Exadata storage is configured for the Autonomous VM cluster. If false, database backup on local Exadata storage is not available in the Autonomous VM cluster.
     * 
     */
    private Boolean isLocalBackupEnabled;
    /**
     * @return The amount of memory (in GBs) to be enabled per each CPU core.
     * 
     */
    private Integer memoryPerOracleComputeUnitInGbs;
    /**
     * @return The memory allocated in GBs.
     * 
     */
    private Integer memorySizeInGbs;
    /**
     * @return The number of non-provisionable Autonomous Container Databases in an Autonomous VM Cluster.
     * 
     */
    private Integer nonProvisionableAutonomousContainerDatabases;
    /**
     * @return The number of provisionable Autonomous Container Databases in an Autonomous VM Cluster.
     * 
     */
    private Integer provisionableAutonomousContainerDatabases;
    /**
     * @return The number of provisioned Autonomous Container Databases in an Autonomous VM Cluster.
     * 
     */
    private Integer provisionedAutonomousContainerDatabases;
    /**
     * @return The number of CPUs provisioned in an Autonomous VM Cluster.
     * 
     */
    private Double provisionedCpus;
    /**
     * @return CPU cores that continue to be included in the count of OCPUs available to the Autonomous Container Database even after one of its Autonomous Database is terminated or scaled down. You can release them to the available OCPUs at its parent AVMC level by restarting the Autonomous Container Database.
     * 
     */
    private Double reclaimableCpus;
    /**
     * @return The number of CPUs reserved in an Autonomous VM Cluster.
     * 
     */
    private Double reservedCpus;
    /**
     * @return The total number of Autonomous Container Databases that can be created.
     * 
     */
    private Integer totalContainerDatabases;
    /**
     * @return The number of CPU cores enabled on the Autonomous VM cluster.
     * 
     */
    private Double totalCpus;
    /**
     * @return The data disk group size used for Autonomous Databases, in TBs.
     * 
     */
    private Double usedAutonomousDataStorageSizeInTbs;
    /**
     * @return The number of CPU cores alloted to the Autonomous Container Databases in an Autonomous VM cluster.
     * 
     */
    private Double usedCpus;

    private GetAutonomousVmClusterResourceUsageResult() {}
    /**
     * @return The data disk group size allocated for Autonomous Databases, in TBs.
     * 
     */
    public Double autonomousDataStorageSizeInTbs() {
        return this.autonomousDataStorageSizeInTbs;
    }
    public String autonomousVmClusterId() {
        return this.autonomousVmClusterId;
    }
    /**
     * @return List of autonomous vm cluster resource usages.
     * 
     */
    public List<GetAutonomousVmClusterResourceUsageAutonomousVmResourceUsage> autonomousVmResourceUsages() {
        return this.autonomousVmResourceUsages;
    }
    /**
     * @return The data disk group size available for Autonomous Databases, in TBs.
     * 
     */
    public Double availableAutonomousDataStorageSizeInTbs() {
        return this.availableAutonomousDataStorageSizeInTbs;
    }
    /**
     * @return The number of CPU cores available.
     * 
     */
    public Double availableCpus() {
        return this.availableCpus;
    }
    /**
     * @return The local node storage allocated in GBs.
     * 
     */
    public Integer dbNodeStorageSizeInGbs() {
        return this.dbNodeStorageSizeInGbs;
    }
    /**
     * @return The user-friendly name for the Autonomous VM cluster. The name does not need to be unique.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Total exadata storage allocated for the Autonomous VM Cluster. DATA + RECOVERY + SPARSE + any overhead in TBs.
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
     * @return If true, database backup on local Exadata storage is configured for the Autonomous VM cluster. If false, database backup on local Exadata storage is not available in the Autonomous VM cluster.
     * 
     */
    public Boolean isLocalBackupEnabled() {
        return this.isLocalBackupEnabled;
    }
    /**
     * @return The amount of memory (in GBs) to be enabled per each CPU core.
     * 
     */
    public Integer memoryPerOracleComputeUnitInGbs() {
        return this.memoryPerOracleComputeUnitInGbs;
    }
    /**
     * @return The memory allocated in GBs.
     * 
     */
    public Integer memorySizeInGbs() {
        return this.memorySizeInGbs;
    }
    /**
     * @return The number of non-provisionable Autonomous Container Databases in an Autonomous VM Cluster.
     * 
     */
    public Integer nonProvisionableAutonomousContainerDatabases() {
        return this.nonProvisionableAutonomousContainerDatabases;
    }
    /**
     * @return The number of provisionable Autonomous Container Databases in an Autonomous VM Cluster.
     * 
     */
    public Integer provisionableAutonomousContainerDatabases() {
        return this.provisionableAutonomousContainerDatabases;
    }
    /**
     * @return The number of provisioned Autonomous Container Databases in an Autonomous VM Cluster.
     * 
     */
    public Integer provisionedAutonomousContainerDatabases() {
        return this.provisionedAutonomousContainerDatabases;
    }
    /**
     * @return The number of CPUs provisioned in an Autonomous VM Cluster.
     * 
     */
    public Double provisionedCpus() {
        return this.provisionedCpus;
    }
    /**
     * @return CPU cores that continue to be included in the count of OCPUs available to the Autonomous Container Database even after one of its Autonomous Database is terminated or scaled down. You can release them to the available OCPUs at its parent AVMC level by restarting the Autonomous Container Database.
     * 
     */
    public Double reclaimableCpus() {
        return this.reclaimableCpus;
    }
    /**
     * @return The number of CPUs reserved in an Autonomous VM Cluster.
     * 
     */
    public Double reservedCpus() {
        return this.reservedCpus;
    }
    /**
     * @return The total number of Autonomous Container Databases that can be created.
     * 
     */
    public Integer totalContainerDatabases() {
        return this.totalContainerDatabases;
    }
    /**
     * @return The number of CPU cores enabled on the Autonomous VM cluster.
     * 
     */
    public Double totalCpus() {
        return this.totalCpus;
    }
    /**
     * @return The data disk group size used for Autonomous Databases, in TBs.
     * 
     */
    public Double usedAutonomousDataStorageSizeInTbs() {
        return this.usedAutonomousDataStorageSizeInTbs;
    }
    /**
     * @return The number of CPU cores alloted to the Autonomous Container Databases in an Autonomous VM cluster.
     * 
     */
    public Double usedCpus() {
        return this.usedCpus;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousVmClusterResourceUsageResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Double autonomousDataStorageSizeInTbs;
        private String autonomousVmClusterId;
        private List<GetAutonomousVmClusterResourceUsageAutonomousVmResourceUsage> autonomousVmResourceUsages;
        private Double availableAutonomousDataStorageSizeInTbs;
        private Double availableCpus;
        private Integer dbNodeStorageSizeInGbs;
        private String displayName;
        private Double exadataStorageInTbs;
        private String id;
        private Boolean isLocalBackupEnabled;
        private Integer memoryPerOracleComputeUnitInGbs;
        private Integer memorySizeInGbs;
        private Integer nonProvisionableAutonomousContainerDatabases;
        private Integer provisionableAutonomousContainerDatabases;
        private Integer provisionedAutonomousContainerDatabases;
        private Double provisionedCpus;
        private Double reclaimableCpus;
        private Double reservedCpus;
        private Integer totalContainerDatabases;
        private Double totalCpus;
        private Double usedAutonomousDataStorageSizeInTbs;
        private Double usedCpus;
        public Builder() {}
        public Builder(GetAutonomousVmClusterResourceUsageResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.autonomousDataStorageSizeInTbs = defaults.autonomousDataStorageSizeInTbs;
    	      this.autonomousVmClusterId = defaults.autonomousVmClusterId;
    	      this.autonomousVmResourceUsages = defaults.autonomousVmResourceUsages;
    	      this.availableAutonomousDataStorageSizeInTbs = defaults.availableAutonomousDataStorageSizeInTbs;
    	      this.availableCpus = defaults.availableCpus;
    	      this.dbNodeStorageSizeInGbs = defaults.dbNodeStorageSizeInGbs;
    	      this.displayName = defaults.displayName;
    	      this.exadataStorageInTbs = defaults.exadataStorageInTbs;
    	      this.id = defaults.id;
    	      this.isLocalBackupEnabled = defaults.isLocalBackupEnabled;
    	      this.memoryPerOracleComputeUnitInGbs = defaults.memoryPerOracleComputeUnitInGbs;
    	      this.memorySizeInGbs = defaults.memorySizeInGbs;
    	      this.nonProvisionableAutonomousContainerDatabases = defaults.nonProvisionableAutonomousContainerDatabases;
    	      this.provisionableAutonomousContainerDatabases = defaults.provisionableAutonomousContainerDatabases;
    	      this.provisionedAutonomousContainerDatabases = defaults.provisionedAutonomousContainerDatabases;
    	      this.provisionedCpus = defaults.provisionedCpus;
    	      this.reclaimableCpus = defaults.reclaimableCpus;
    	      this.reservedCpus = defaults.reservedCpus;
    	      this.totalContainerDatabases = defaults.totalContainerDatabases;
    	      this.totalCpus = defaults.totalCpus;
    	      this.usedAutonomousDataStorageSizeInTbs = defaults.usedAutonomousDataStorageSizeInTbs;
    	      this.usedCpus = defaults.usedCpus;
        }

        @CustomType.Setter
        public Builder autonomousDataStorageSizeInTbs(Double autonomousDataStorageSizeInTbs) {
            if (autonomousDataStorageSizeInTbs == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "autonomousDataStorageSizeInTbs");
            }
            this.autonomousDataStorageSizeInTbs = autonomousDataStorageSizeInTbs;
            return this;
        }
        @CustomType.Setter
        public Builder autonomousVmClusterId(String autonomousVmClusterId) {
            if (autonomousVmClusterId == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "autonomousVmClusterId");
            }
            this.autonomousVmClusterId = autonomousVmClusterId;
            return this;
        }
        @CustomType.Setter
        public Builder autonomousVmResourceUsages(List<GetAutonomousVmClusterResourceUsageAutonomousVmResourceUsage> autonomousVmResourceUsages) {
            if (autonomousVmResourceUsages == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "autonomousVmResourceUsages");
            }
            this.autonomousVmResourceUsages = autonomousVmResourceUsages;
            return this;
        }
        public Builder autonomousVmResourceUsages(GetAutonomousVmClusterResourceUsageAutonomousVmResourceUsage... autonomousVmResourceUsages) {
            return autonomousVmResourceUsages(List.of(autonomousVmResourceUsages));
        }
        @CustomType.Setter
        public Builder availableAutonomousDataStorageSizeInTbs(Double availableAutonomousDataStorageSizeInTbs) {
            if (availableAutonomousDataStorageSizeInTbs == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "availableAutonomousDataStorageSizeInTbs");
            }
            this.availableAutonomousDataStorageSizeInTbs = availableAutonomousDataStorageSizeInTbs;
            return this;
        }
        @CustomType.Setter
        public Builder availableCpus(Double availableCpus) {
            if (availableCpus == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "availableCpus");
            }
            this.availableCpus = availableCpus;
            return this;
        }
        @CustomType.Setter
        public Builder dbNodeStorageSizeInGbs(Integer dbNodeStorageSizeInGbs) {
            if (dbNodeStorageSizeInGbs == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "dbNodeStorageSizeInGbs");
            }
            this.dbNodeStorageSizeInGbs = dbNodeStorageSizeInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder exadataStorageInTbs(Double exadataStorageInTbs) {
            if (exadataStorageInTbs == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "exadataStorageInTbs");
            }
            this.exadataStorageInTbs = exadataStorageInTbs;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder isLocalBackupEnabled(Boolean isLocalBackupEnabled) {
            if (isLocalBackupEnabled == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "isLocalBackupEnabled");
            }
            this.isLocalBackupEnabled = isLocalBackupEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder memoryPerOracleComputeUnitInGbs(Integer memoryPerOracleComputeUnitInGbs) {
            if (memoryPerOracleComputeUnitInGbs == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "memoryPerOracleComputeUnitInGbs");
            }
            this.memoryPerOracleComputeUnitInGbs = memoryPerOracleComputeUnitInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder memorySizeInGbs(Integer memorySizeInGbs) {
            if (memorySizeInGbs == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "memorySizeInGbs");
            }
            this.memorySizeInGbs = memorySizeInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder nonProvisionableAutonomousContainerDatabases(Integer nonProvisionableAutonomousContainerDatabases) {
            if (nonProvisionableAutonomousContainerDatabases == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "nonProvisionableAutonomousContainerDatabases");
            }
            this.nonProvisionableAutonomousContainerDatabases = nonProvisionableAutonomousContainerDatabases;
            return this;
        }
        @CustomType.Setter
        public Builder provisionableAutonomousContainerDatabases(Integer provisionableAutonomousContainerDatabases) {
            if (provisionableAutonomousContainerDatabases == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "provisionableAutonomousContainerDatabases");
            }
            this.provisionableAutonomousContainerDatabases = provisionableAutonomousContainerDatabases;
            return this;
        }
        @CustomType.Setter
        public Builder provisionedAutonomousContainerDatabases(Integer provisionedAutonomousContainerDatabases) {
            if (provisionedAutonomousContainerDatabases == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "provisionedAutonomousContainerDatabases");
            }
            this.provisionedAutonomousContainerDatabases = provisionedAutonomousContainerDatabases;
            return this;
        }
        @CustomType.Setter
        public Builder provisionedCpus(Double provisionedCpus) {
            if (provisionedCpus == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "provisionedCpus");
            }
            this.provisionedCpus = provisionedCpus;
            return this;
        }
        @CustomType.Setter
        public Builder reclaimableCpus(Double reclaimableCpus) {
            if (reclaimableCpus == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "reclaimableCpus");
            }
            this.reclaimableCpus = reclaimableCpus;
            return this;
        }
        @CustomType.Setter
        public Builder reservedCpus(Double reservedCpus) {
            if (reservedCpus == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "reservedCpus");
            }
            this.reservedCpus = reservedCpus;
            return this;
        }
        @CustomType.Setter
        public Builder totalContainerDatabases(Integer totalContainerDatabases) {
            if (totalContainerDatabases == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "totalContainerDatabases");
            }
            this.totalContainerDatabases = totalContainerDatabases;
            return this;
        }
        @CustomType.Setter
        public Builder totalCpus(Double totalCpus) {
            if (totalCpus == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "totalCpus");
            }
            this.totalCpus = totalCpus;
            return this;
        }
        @CustomType.Setter
        public Builder usedAutonomousDataStorageSizeInTbs(Double usedAutonomousDataStorageSizeInTbs) {
            if (usedAutonomousDataStorageSizeInTbs == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "usedAutonomousDataStorageSizeInTbs");
            }
            this.usedAutonomousDataStorageSizeInTbs = usedAutonomousDataStorageSizeInTbs;
            return this;
        }
        @CustomType.Setter
        public Builder usedCpus(Double usedCpus) {
            if (usedCpus == null) {
              throw new MissingRequiredPropertyException("GetAutonomousVmClusterResourceUsageResult", "usedCpus");
            }
            this.usedCpus = usedCpus;
            return this;
        }
        public GetAutonomousVmClusterResourceUsageResult build() {
            final var _resultValue = new GetAutonomousVmClusterResourceUsageResult();
            _resultValue.autonomousDataStorageSizeInTbs = autonomousDataStorageSizeInTbs;
            _resultValue.autonomousVmClusterId = autonomousVmClusterId;
            _resultValue.autonomousVmResourceUsages = autonomousVmResourceUsages;
            _resultValue.availableAutonomousDataStorageSizeInTbs = availableAutonomousDataStorageSizeInTbs;
            _resultValue.availableCpus = availableCpus;
            _resultValue.dbNodeStorageSizeInGbs = dbNodeStorageSizeInGbs;
            _resultValue.displayName = displayName;
            _resultValue.exadataStorageInTbs = exadataStorageInTbs;
            _resultValue.id = id;
            _resultValue.isLocalBackupEnabled = isLocalBackupEnabled;
            _resultValue.memoryPerOracleComputeUnitInGbs = memoryPerOracleComputeUnitInGbs;
            _resultValue.memorySizeInGbs = memorySizeInGbs;
            _resultValue.nonProvisionableAutonomousContainerDatabases = nonProvisionableAutonomousContainerDatabases;
            _resultValue.provisionableAutonomousContainerDatabases = provisionableAutonomousContainerDatabases;
            _resultValue.provisionedAutonomousContainerDatabases = provisionedAutonomousContainerDatabases;
            _resultValue.provisionedCpus = provisionedCpus;
            _resultValue.reclaimableCpus = reclaimableCpus;
            _resultValue.reservedCpus = reservedCpus;
            _resultValue.totalContainerDatabases = totalContainerDatabases;
            _resultValue.totalCpus = totalCpus;
            _resultValue.usedAutonomousDataStorageSizeInTbs = usedAutonomousDataStorageSizeInTbs;
            _resultValue.usedCpus = usedCpus;
            return _resultValue;
        }
    }
}
