// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Mysql.outputs.MysqlBackupDbSystemSnapshotBackupPolicy;
import com.pulumi.oci.Mysql.outputs.MysqlBackupDbSystemSnapshotDeletionPolicy;
import com.pulumi.oci.Mysql.outputs.MysqlBackupDbSystemSnapshotEndpoint;
import com.pulumi.oci.Mysql.outputs.MysqlBackupDbSystemSnapshotMaintenance;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MysqlBackupDbSystemSnapshot {
    /**
     * @return The username for the administrative user.
     * 
     */
    private @Nullable String adminUsername;
    /**
     * @return The Availability Domain where the primary DB System should be located.
     * 
     */
    private @Nullable String availabilityDomain;
    /**
     * @return The Backup policy for the DB System.
     * 
     */
    private @Nullable List<MysqlBackupDbSystemSnapshotBackupPolicy> backupPolicies;
    /**
     * @return (Updatable) The OCID of the compartment.
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return The OCID of the Configuration to be used for Instances in this DB System.
     * 
     */
    private @Nullable String configurationId;
    /**
     * @return Whether to run the DB System with InnoDB Redo Logs and the Double Write Buffer enabled or disabled, and whether to enable or disable syncing of the Binary Logs.
     * 
     */
    private @Nullable String crashRecovery;
    /**
     * @return Initial size of the data volume in GiBs that will be created and attached.
     * 
     */
    private @Nullable Integer dataStorageSizeInGb;
    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private @Nullable Map<String,Object> definedTags;
    /**
     * @return The Deletion policy for the DB System.
     * 
     */
    private @Nullable List<MysqlBackupDbSystemSnapshotDeletionPolicy> deletionPolicies;
    /**
     * @return (Updatable) A user-supplied description for the backup.
     * 
     */
    private @Nullable String description;
    /**
     * @return (Updatable) A user-supplied display name for the backup.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The network endpoints available for this DB System.
     * 
     */
    private @Nullable List<MysqlBackupDbSystemSnapshotEndpoint> endpoints;
    /**
     * @return The name of the Fault Domain the DB System is located in.
     * 
     */
    private @Nullable String faultDomain;
    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private @Nullable Map<String,Object> freeformTags;
    /**
     * @return The hostname for the primary endpoint of the DB System. Used for DNS. The value is the hostname portion of the primary private IP&#39;s fully qualified domain name (FQDN) (for example, &#34;dbsystem-1&#34; in FQDN &#34;dbsystem-1.subnet123.vcn1.oraclevcn.com&#34;). Must be unique across all VNICs in the subnet and comply with RFC 952 and RFC 1123.
     * 
     */
    private @Nullable String hostnameLabel;
    /**
     * @return OCID of the backup itself
     * 
     */
    private @Nullable String id;
    /**
     * @return The IP address the DB System is configured to listen on. A private IP address of the primary endpoint of the DB System. Must be an available IP address within the subnet&#39;s CIDR. This will be a &#34;dotted-quad&#34; style IPv4 address.
     * 
     */
    private @Nullable String ipAddress;
    /**
     * @return Specifies if the DB System is highly available.
     * 
     */
    private @Nullable Boolean isHighlyAvailable;
    /**
     * @return The Maintenance Policy for the DB System.
     * 
     */
    private @Nullable List<MysqlBackupDbSystemSnapshotMaintenance> maintenances;
    /**
     * @return The MySQL server version of the DB System used for backup.
     * 
     */
    private @Nullable String mysqlVersion;
    /**
     * @return The port for primary endpoint of the DB System to listen on.
     * 
     */
    private @Nullable Integer port;
    /**
     * @return The network port on which X Plugin listens for TCP/IP connections. This is the X Plugin equivalent of port.
     * 
     */
    private @Nullable Integer portX;
    /**
     * @return The shape of the DB System instance used for backup.
     * 
     */
    private @Nullable String shapeName;
    /**
     * @return The OCID of the subnet the DB System is associated with.
     * 
     */
    private @Nullable String subnetId;

    private MysqlBackupDbSystemSnapshot() {}
    /**
     * @return The username for the administrative user.
     * 
     */
    public Optional<String> adminUsername() {
        return Optional.ofNullable(this.adminUsername);
    }
    /**
     * @return The Availability Domain where the primary DB System should be located.
     * 
     */
    public Optional<String> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }
    /**
     * @return The Backup policy for the DB System.
     * 
     */
    public List<MysqlBackupDbSystemSnapshotBackupPolicy> backupPolicies() {
        return this.backupPolicies == null ? List.of() : this.backupPolicies;
    }
    /**
     * @return (Updatable) The OCID of the compartment.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return The OCID of the Configuration to be used for Instances in this DB System.
     * 
     */
    public Optional<String> configurationId() {
        return Optional.ofNullable(this.configurationId);
    }
    /**
     * @return Whether to run the DB System with InnoDB Redo Logs and the Double Write Buffer enabled or disabled, and whether to enable or disable syncing of the Binary Logs.
     * 
     */
    public Optional<String> crashRecovery() {
        return Optional.ofNullable(this.crashRecovery);
    }
    /**
     * @return Initial size of the data volume in GiBs that will be created and attached.
     * 
     */
    public Optional<Integer> dataStorageSizeInGb() {
        return Optional.ofNullable(this.dataStorageSizeInGb);
    }
    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags == null ? Map.of() : this.definedTags;
    }
    /**
     * @return The Deletion policy for the DB System.
     * 
     */
    public List<MysqlBackupDbSystemSnapshotDeletionPolicy> deletionPolicies() {
        return this.deletionPolicies == null ? List.of() : this.deletionPolicies;
    }
    /**
     * @return (Updatable) A user-supplied description for the backup.
     * 
     */
    public Optional<String> description() {
        return Optional.ofNullable(this.description);
    }
    /**
     * @return (Updatable) A user-supplied display name for the backup.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The network endpoints available for this DB System.
     * 
     */
    public List<MysqlBackupDbSystemSnapshotEndpoint> endpoints() {
        return this.endpoints == null ? List.of() : this.endpoints;
    }
    /**
     * @return The name of the Fault Domain the DB System is located in.
     * 
     */
    public Optional<String> faultDomain() {
        return Optional.ofNullable(this.faultDomain);
    }
    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags == null ? Map.of() : this.freeformTags;
    }
    /**
     * @return The hostname for the primary endpoint of the DB System. Used for DNS. The value is the hostname portion of the primary private IP&#39;s fully qualified domain name (FQDN) (for example, &#34;dbsystem-1&#34; in FQDN &#34;dbsystem-1.subnet123.vcn1.oraclevcn.com&#34;). Must be unique across all VNICs in the subnet and comply with RFC 952 and RFC 1123.
     * 
     */
    public Optional<String> hostnameLabel() {
        return Optional.ofNullable(this.hostnameLabel);
    }
    /**
     * @return OCID of the backup itself
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The IP address the DB System is configured to listen on. A private IP address of the primary endpoint of the DB System. Must be an available IP address within the subnet&#39;s CIDR. This will be a &#34;dotted-quad&#34; style IPv4 address.
     * 
     */
    public Optional<String> ipAddress() {
        return Optional.ofNullable(this.ipAddress);
    }
    /**
     * @return Specifies if the DB System is highly available.
     * 
     */
    public Optional<Boolean> isHighlyAvailable() {
        return Optional.ofNullable(this.isHighlyAvailable);
    }
    /**
     * @return The Maintenance Policy for the DB System.
     * 
     */
    public List<MysqlBackupDbSystemSnapshotMaintenance> maintenances() {
        return this.maintenances == null ? List.of() : this.maintenances;
    }
    /**
     * @return The MySQL server version of the DB System used for backup.
     * 
     */
    public Optional<String> mysqlVersion() {
        return Optional.ofNullable(this.mysqlVersion);
    }
    /**
     * @return The port for primary endpoint of the DB System to listen on.
     * 
     */
    public Optional<Integer> port() {
        return Optional.ofNullable(this.port);
    }
    /**
     * @return The network port on which X Plugin listens for TCP/IP connections. This is the X Plugin equivalent of port.
     * 
     */
    public Optional<Integer> portX() {
        return Optional.ofNullable(this.portX);
    }
    /**
     * @return The shape of the DB System instance used for backup.
     * 
     */
    public Optional<String> shapeName() {
        return Optional.ofNullable(this.shapeName);
    }
    /**
     * @return The OCID of the subnet the DB System is associated with.
     * 
     */
    public Optional<String> subnetId() {
        return Optional.ofNullable(this.subnetId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MysqlBackupDbSystemSnapshot defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String adminUsername;
        private @Nullable String availabilityDomain;
        private @Nullable List<MysqlBackupDbSystemSnapshotBackupPolicy> backupPolicies;
        private @Nullable String compartmentId;
        private @Nullable String configurationId;
        private @Nullable String crashRecovery;
        private @Nullable Integer dataStorageSizeInGb;
        private @Nullable Map<String,Object> definedTags;
        private @Nullable List<MysqlBackupDbSystemSnapshotDeletionPolicy> deletionPolicies;
        private @Nullable String description;
        private @Nullable String displayName;
        private @Nullable List<MysqlBackupDbSystemSnapshotEndpoint> endpoints;
        private @Nullable String faultDomain;
        private @Nullable Map<String,Object> freeformTags;
        private @Nullable String hostnameLabel;
        private @Nullable String id;
        private @Nullable String ipAddress;
        private @Nullable Boolean isHighlyAvailable;
        private @Nullable List<MysqlBackupDbSystemSnapshotMaintenance> maintenances;
        private @Nullable String mysqlVersion;
        private @Nullable Integer port;
        private @Nullable Integer portX;
        private @Nullable String shapeName;
        private @Nullable String subnetId;
        public Builder() {}
        public Builder(MysqlBackupDbSystemSnapshot defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adminUsername = defaults.adminUsername;
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.backupPolicies = defaults.backupPolicies;
    	      this.compartmentId = defaults.compartmentId;
    	      this.configurationId = defaults.configurationId;
    	      this.crashRecovery = defaults.crashRecovery;
    	      this.dataStorageSizeInGb = defaults.dataStorageSizeInGb;
    	      this.definedTags = defaults.definedTags;
    	      this.deletionPolicies = defaults.deletionPolicies;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.endpoints = defaults.endpoints;
    	      this.faultDomain = defaults.faultDomain;
    	      this.freeformTags = defaults.freeformTags;
    	      this.hostnameLabel = defaults.hostnameLabel;
    	      this.id = defaults.id;
    	      this.ipAddress = defaults.ipAddress;
    	      this.isHighlyAvailable = defaults.isHighlyAvailable;
    	      this.maintenances = defaults.maintenances;
    	      this.mysqlVersion = defaults.mysqlVersion;
    	      this.port = defaults.port;
    	      this.portX = defaults.portX;
    	      this.shapeName = defaults.shapeName;
    	      this.subnetId = defaults.subnetId;
        }

        @CustomType.Setter
        public Builder adminUsername(@Nullable String adminUsername) {
            this.adminUsername = adminUsername;
            return this;
        }
        @CustomType.Setter
        public Builder availabilityDomain(@Nullable String availabilityDomain) {
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder backupPolicies(@Nullable List<MysqlBackupDbSystemSnapshotBackupPolicy> backupPolicies) {
            this.backupPolicies = backupPolicies;
            return this;
        }
        public Builder backupPolicies(MysqlBackupDbSystemSnapshotBackupPolicy... backupPolicies) {
            return backupPolicies(List.of(backupPolicies));
        }
        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder configurationId(@Nullable String configurationId) {
            this.configurationId = configurationId;
            return this;
        }
        @CustomType.Setter
        public Builder crashRecovery(@Nullable String crashRecovery) {
            this.crashRecovery = crashRecovery;
            return this;
        }
        @CustomType.Setter
        public Builder dataStorageSizeInGb(@Nullable Integer dataStorageSizeInGb) {
            this.dataStorageSizeInGb = dataStorageSizeInGb;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(@Nullable Map<String,Object> definedTags) {
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder deletionPolicies(@Nullable List<MysqlBackupDbSystemSnapshotDeletionPolicy> deletionPolicies) {
            this.deletionPolicies = deletionPolicies;
            return this;
        }
        public Builder deletionPolicies(MysqlBackupDbSystemSnapshotDeletionPolicy... deletionPolicies) {
            return deletionPolicies(List.of(deletionPolicies));
        }
        @CustomType.Setter
        public Builder description(@Nullable String description) {
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder endpoints(@Nullable List<MysqlBackupDbSystemSnapshotEndpoint> endpoints) {
            this.endpoints = endpoints;
            return this;
        }
        public Builder endpoints(MysqlBackupDbSystemSnapshotEndpoint... endpoints) {
            return endpoints(List.of(endpoints));
        }
        @CustomType.Setter
        public Builder faultDomain(@Nullable String faultDomain) {
            this.faultDomain = faultDomain;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(@Nullable Map<String,Object> freeformTags) {
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder hostnameLabel(@Nullable String hostnameLabel) {
            this.hostnameLabel = hostnameLabel;
            return this;
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder ipAddress(@Nullable String ipAddress) {
            this.ipAddress = ipAddress;
            return this;
        }
        @CustomType.Setter
        public Builder isHighlyAvailable(@Nullable Boolean isHighlyAvailable) {
            this.isHighlyAvailable = isHighlyAvailable;
            return this;
        }
        @CustomType.Setter
        public Builder maintenances(@Nullable List<MysqlBackupDbSystemSnapshotMaintenance> maintenances) {
            this.maintenances = maintenances;
            return this;
        }
        public Builder maintenances(MysqlBackupDbSystemSnapshotMaintenance... maintenances) {
            return maintenances(List.of(maintenances));
        }
        @CustomType.Setter
        public Builder mysqlVersion(@Nullable String mysqlVersion) {
            this.mysqlVersion = mysqlVersion;
            return this;
        }
        @CustomType.Setter
        public Builder port(@Nullable Integer port) {
            this.port = port;
            return this;
        }
        @CustomType.Setter
        public Builder portX(@Nullable Integer portX) {
            this.portX = portX;
            return this;
        }
        @CustomType.Setter
        public Builder shapeName(@Nullable String shapeName) {
            this.shapeName = shapeName;
            return this;
        }
        @CustomType.Setter
        public Builder subnetId(@Nullable String subnetId) {
            this.subnetId = subnetId;
            return this;
        }
        public MysqlBackupDbSystemSnapshot build() {
            final var o = new MysqlBackupDbSystemSnapshot();
            o.adminUsername = adminUsername;
            o.availabilityDomain = availabilityDomain;
            o.backupPolicies = backupPolicies;
            o.compartmentId = compartmentId;
            o.configurationId = configurationId;
            o.crashRecovery = crashRecovery;
            o.dataStorageSizeInGb = dataStorageSizeInGb;
            o.definedTags = definedTags;
            o.deletionPolicies = deletionPolicies;
            o.description = description;
            o.displayName = displayName;
            o.endpoints = endpoints;
            o.faultDomain = faultDomain;
            o.freeformTags = freeformTags;
            o.hostnameLabel = hostnameLabel;
            o.id = id;
            o.ipAddress = ipAddress;
            o.isHighlyAvailable = isHighlyAvailable;
            o.maintenances = maintenances;
            o.mysqlVersion = mysqlVersion;
            o.port = port;
            o.portX = portX;
            o.shapeName = shapeName;
            o.subnetId = subnetId;
            return o;
        }
    }
}