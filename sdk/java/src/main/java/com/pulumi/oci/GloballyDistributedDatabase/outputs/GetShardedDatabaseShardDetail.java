// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GloballyDistributedDatabase.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.GloballyDistributedDatabase.outputs.GetShardedDatabaseShardDetailEncryptionKeyDetail;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetShardedDatabaseShardDetail {
    private String adminPassword;
    /**
     * @return Identifier of the primary cloudAutonomousVmCluster for the shard.
     * 
     */
    private String cloudAutonomousVmClusterId;
    /**
     * @return The compute amount available to the underlying autonomous database associated with shard.
     * 
     */
    private Double computeCount;
    /**
     * @return Identifier of the underlying container database.
     * 
     */
    private String containerDatabaseId;
    /**
     * @return Identifier of the underlying container database parent.
     * 
     */
    private String containerDatabaseParentId;
    /**
     * @return The data disk group size to be allocated in GBs.
     * 
     */
    private Double dataStorageSizeInGbs;
    /**
     * @return Details of encryption key to be used to encrypt data for shards and catalog for sharded database. For system-defined sharding type, all shards have to use same encryptionKeyDetails. For system-defined sharding, if encryptionKeyDetails are not specified for catalog, then Oracle managed key will be used for catalog. For user-defined sharding type, if encryptionKeyDetails are not provided for any shard or catalog, then Oracle managed key will be used for such shard or catalog. For system-defined or user-defined sharding type, if the shard or catalog has a peer in region other than primary shard or catalog region, then make sure to provide virtual vault for such shard or catalog, which is also replicated to peer region (the region where peer or standby shard or catalog exists).
     * 
     */
    private List<GetShardedDatabaseShardDetailEncryptionKeyDetail> encryptionKeyDetails;
    /**
     * @return Determines the auto-scaling mode.
     * 
     */
    private Boolean isAutoScalingEnabled;
    /**
     * @return Comma separated names of argument corresponding to which metadata need to be retrived, namely VM_CLUSTER_INFO, ADDITIONAL_RESOURCE_INFO. An example is metadata=VM_CLUSTER_INFO,ADDITIONAL_RESOURCE_INFO.
     * 
     */
    private Map<String,String> metadata;
    /**
     * @return Name of the shard.
     * 
     */
    private String name;
    /**
     * @return Identifier of the peer cloudAutonomousVmCluster for the shard.
     * 
     */
    private String peerCloudAutonomousVmClusterId;
    /**
     * @return Name of the shard-group to which the shard belongs.
     * 
     */
    private String shardGroup;
    /**
     * @return Shard space name.
     * 
     */
    private String shardSpace;
    /**
     * @return Status of shard or catalog or gsm for the sharded database.
     * 
     */
    private String status;
    /**
     * @return Identifier of the underlying supporting resource.
     * 
     */
    private String supportingResourceId;
    /**
     * @return The time the the Sharded Database was created. An RFC3339 formatted datetime string
     * 
     */
    private String timeCreated;
    /**
     * @return The time the ssl certificate associated with shard expires. An RFC3339 formatted datetime string
     * 
     */
    private String timeSslCertificateExpires;
    /**
     * @return The time the Sharded Database was last updated. An RFC3339 formatted datetime string
     * 
     */
    private String timeUpdated;

    private GetShardedDatabaseShardDetail() {}
    public String adminPassword() {
        return this.adminPassword;
    }
    /**
     * @return Identifier of the primary cloudAutonomousVmCluster for the shard.
     * 
     */
    public String cloudAutonomousVmClusterId() {
        return this.cloudAutonomousVmClusterId;
    }
    /**
     * @return The compute amount available to the underlying autonomous database associated with shard.
     * 
     */
    public Double computeCount() {
        return this.computeCount;
    }
    /**
     * @return Identifier of the underlying container database.
     * 
     */
    public String containerDatabaseId() {
        return this.containerDatabaseId;
    }
    /**
     * @return Identifier of the underlying container database parent.
     * 
     */
    public String containerDatabaseParentId() {
        return this.containerDatabaseParentId;
    }
    /**
     * @return The data disk group size to be allocated in GBs.
     * 
     */
    public Double dataStorageSizeInGbs() {
        return this.dataStorageSizeInGbs;
    }
    /**
     * @return Details of encryption key to be used to encrypt data for shards and catalog for sharded database. For system-defined sharding type, all shards have to use same encryptionKeyDetails. For system-defined sharding, if encryptionKeyDetails are not specified for catalog, then Oracle managed key will be used for catalog. For user-defined sharding type, if encryptionKeyDetails are not provided for any shard or catalog, then Oracle managed key will be used for such shard or catalog. For system-defined or user-defined sharding type, if the shard or catalog has a peer in region other than primary shard or catalog region, then make sure to provide virtual vault for such shard or catalog, which is also replicated to peer region (the region where peer or standby shard or catalog exists).
     * 
     */
    public List<GetShardedDatabaseShardDetailEncryptionKeyDetail> encryptionKeyDetails() {
        return this.encryptionKeyDetails;
    }
    /**
     * @return Determines the auto-scaling mode.
     * 
     */
    public Boolean isAutoScalingEnabled() {
        return this.isAutoScalingEnabled;
    }
    /**
     * @return Comma separated names of argument corresponding to which metadata need to be retrived, namely VM_CLUSTER_INFO, ADDITIONAL_RESOURCE_INFO. An example is metadata=VM_CLUSTER_INFO,ADDITIONAL_RESOURCE_INFO.
     * 
     */
    public Map<String,String> metadata() {
        return this.metadata;
    }
    /**
     * @return Name of the shard.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Identifier of the peer cloudAutonomousVmCluster for the shard.
     * 
     */
    public String peerCloudAutonomousVmClusterId() {
        return this.peerCloudAutonomousVmClusterId;
    }
    /**
     * @return Name of the shard-group to which the shard belongs.
     * 
     */
    public String shardGroup() {
        return this.shardGroup;
    }
    /**
     * @return Shard space name.
     * 
     */
    public String shardSpace() {
        return this.shardSpace;
    }
    /**
     * @return Status of shard or catalog or gsm for the sharded database.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return Identifier of the underlying supporting resource.
     * 
     */
    public String supportingResourceId() {
        return this.supportingResourceId;
    }
    /**
     * @return The time the the Sharded Database was created. An RFC3339 formatted datetime string
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the ssl certificate associated with shard expires. An RFC3339 formatted datetime string
     * 
     */
    public String timeSslCertificateExpires() {
        return this.timeSslCertificateExpires;
    }
    /**
     * @return The time the Sharded Database was last updated. An RFC3339 formatted datetime string
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetShardedDatabaseShardDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String adminPassword;
        private String cloudAutonomousVmClusterId;
        private Double computeCount;
        private String containerDatabaseId;
        private String containerDatabaseParentId;
        private Double dataStorageSizeInGbs;
        private List<GetShardedDatabaseShardDetailEncryptionKeyDetail> encryptionKeyDetails;
        private Boolean isAutoScalingEnabled;
        private Map<String,String> metadata;
        private String name;
        private String peerCloudAutonomousVmClusterId;
        private String shardGroup;
        private String shardSpace;
        private String status;
        private String supportingResourceId;
        private String timeCreated;
        private String timeSslCertificateExpires;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetShardedDatabaseShardDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adminPassword = defaults.adminPassword;
    	      this.cloudAutonomousVmClusterId = defaults.cloudAutonomousVmClusterId;
    	      this.computeCount = defaults.computeCount;
    	      this.containerDatabaseId = defaults.containerDatabaseId;
    	      this.containerDatabaseParentId = defaults.containerDatabaseParentId;
    	      this.dataStorageSizeInGbs = defaults.dataStorageSizeInGbs;
    	      this.encryptionKeyDetails = defaults.encryptionKeyDetails;
    	      this.isAutoScalingEnabled = defaults.isAutoScalingEnabled;
    	      this.metadata = defaults.metadata;
    	      this.name = defaults.name;
    	      this.peerCloudAutonomousVmClusterId = defaults.peerCloudAutonomousVmClusterId;
    	      this.shardGroup = defaults.shardGroup;
    	      this.shardSpace = defaults.shardSpace;
    	      this.status = defaults.status;
    	      this.supportingResourceId = defaults.supportingResourceId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeSslCertificateExpires = defaults.timeSslCertificateExpires;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder adminPassword(String adminPassword) {
            if (adminPassword == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "adminPassword");
            }
            this.adminPassword = adminPassword;
            return this;
        }
        @CustomType.Setter
        public Builder cloudAutonomousVmClusterId(String cloudAutonomousVmClusterId) {
            if (cloudAutonomousVmClusterId == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "cloudAutonomousVmClusterId");
            }
            this.cloudAutonomousVmClusterId = cloudAutonomousVmClusterId;
            return this;
        }
        @CustomType.Setter
        public Builder computeCount(Double computeCount) {
            if (computeCount == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "computeCount");
            }
            this.computeCount = computeCount;
            return this;
        }
        @CustomType.Setter
        public Builder containerDatabaseId(String containerDatabaseId) {
            if (containerDatabaseId == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "containerDatabaseId");
            }
            this.containerDatabaseId = containerDatabaseId;
            return this;
        }
        @CustomType.Setter
        public Builder containerDatabaseParentId(String containerDatabaseParentId) {
            if (containerDatabaseParentId == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "containerDatabaseParentId");
            }
            this.containerDatabaseParentId = containerDatabaseParentId;
            return this;
        }
        @CustomType.Setter
        public Builder dataStorageSizeInGbs(Double dataStorageSizeInGbs) {
            if (dataStorageSizeInGbs == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "dataStorageSizeInGbs");
            }
            this.dataStorageSizeInGbs = dataStorageSizeInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder encryptionKeyDetails(List<GetShardedDatabaseShardDetailEncryptionKeyDetail> encryptionKeyDetails) {
            if (encryptionKeyDetails == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "encryptionKeyDetails");
            }
            this.encryptionKeyDetails = encryptionKeyDetails;
            return this;
        }
        public Builder encryptionKeyDetails(GetShardedDatabaseShardDetailEncryptionKeyDetail... encryptionKeyDetails) {
            return encryptionKeyDetails(List.of(encryptionKeyDetails));
        }
        @CustomType.Setter
        public Builder isAutoScalingEnabled(Boolean isAutoScalingEnabled) {
            if (isAutoScalingEnabled == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "isAutoScalingEnabled");
            }
            this.isAutoScalingEnabled = isAutoScalingEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder metadata(Map<String,String> metadata) {
            if (metadata == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "metadata");
            }
            this.metadata = metadata;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder peerCloudAutonomousVmClusterId(String peerCloudAutonomousVmClusterId) {
            if (peerCloudAutonomousVmClusterId == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "peerCloudAutonomousVmClusterId");
            }
            this.peerCloudAutonomousVmClusterId = peerCloudAutonomousVmClusterId;
            return this;
        }
        @CustomType.Setter
        public Builder shardGroup(String shardGroup) {
            if (shardGroup == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "shardGroup");
            }
            this.shardGroup = shardGroup;
            return this;
        }
        @CustomType.Setter
        public Builder shardSpace(String shardSpace) {
            if (shardSpace == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "shardSpace");
            }
            this.shardSpace = shardSpace;
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            if (status == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder supportingResourceId(String supportingResourceId) {
            if (supportingResourceId == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "supportingResourceId");
            }
            this.supportingResourceId = supportingResourceId;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeSslCertificateExpires(String timeSslCertificateExpires) {
            if (timeSslCertificateExpires == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "timeSslCertificateExpires");
            }
            this.timeSslCertificateExpires = timeSslCertificateExpires;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabaseShardDetail", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        public GetShardedDatabaseShardDetail build() {
            final var _resultValue = new GetShardedDatabaseShardDetail();
            _resultValue.adminPassword = adminPassword;
            _resultValue.cloudAutonomousVmClusterId = cloudAutonomousVmClusterId;
            _resultValue.computeCount = computeCount;
            _resultValue.containerDatabaseId = containerDatabaseId;
            _resultValue.containerDatabaseParentId = containerDatabaseParentId;
            _resultValue.dataStorageSizeInGbs = dataStorageSizeInGbs;
            _resultValue.encryptionKeyDetails = encryptionKeyDetails;
            _resultValue.isAutoScalingEnabled = isAutoScalingEnabled;
            _resultValue.metadata = metadata;
            _resultValue.name = name;
            _resultValue.peerCloudAutonomousVmClusterId = peerCloudAutonomousVmClusterId;
            _resultValue.shardGroup = shardGroup;
            _resultValue.shardSpace = shardSpace;
            _resultValue.status = status;
            _resultValue.supportingResourceId = supportingResourceId;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeSslCertificateExpires = timeSslCertificateExpires;
            _resultValue.timeUpdated = timeUpdated;
            return _resultValue;
        }
    }
}
