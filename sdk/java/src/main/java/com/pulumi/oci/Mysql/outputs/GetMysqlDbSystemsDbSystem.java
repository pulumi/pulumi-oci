// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Mysql.outputs.GetMysqlDbSystemsDbSystemAnalyticsCluster;
import com.pulumi.oci.Mysql.outputs.GetMysqlDbSystemsDbSystemBackupPolicy;
import com.pulumi.oci.Mysql.outputs.GetMysqlDbSystemsDbSystemChannel;
import com.pulumi.oci.Mysql.outputs.GetMysqlDbSystemsDbSystemCurrentPlacement;
import com.pulumi.oci.Mysql.outputs.GetMysqlDbSystemsDbSystemDeletionPolicy;
import com.pulumi.oci.Mysql.outputs.GetMysqlDbSystemsDbSystemEndpoint;
import com.pulumi.oci.Mysql.outputs.GetMysqlDbSystemsDbSystemHeatWaveCluster;
import com.pulumi.oci.Mysql.outputs.GetMysqlDbSystemsDbSystemMaintenance;
import com.pulumi.oci.Mysql.outputs.GetMysqlDbSystemsDbSystemPointInTimeRecoveryDetail;
import com.pulumi.oci.Mysql.outputs.GetMysqlDbSystemsDbSystemSource;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetMysqlDbSystemsDbSystem {
    private String adminPassword;
    private String adminUsername;
    /**
     * @return DEPRECATED -- please use HeatWave API instead. A summary of an Analytics Cluster.
     * 
     */
    private List<GetMysqlDbSystemsDbSystemAnalyticsCluster> analyticsClusters;
    /**
     * @return The availability domain in which the DB System is placed.
     * 
     */
    private String availabilityDomain;
    /**
     * @return The Backup policy for the DB System.
     * 
     */
    private List<GetMysqlDbSystemsDbSystemBackupPolicy> backupPolicies;
    /**
     * @return A list with a summary of all the Channels attached to the DB System.
     * 
     */
    private List<GetMysqlDbSystemsDbSystemChannel> channels;
    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    private String compartmentId;
    /**
     * @return The requested Configuration instance.
     * 
     */
    private String configurationId;
    /**
     * @return Whether to run the DB System with InnoDB Redo Logs and the Double Write Buffer enabled or disabled, and whether to enable or disable syncing of the Binary Logs.
     * 
     */
    private String crashRecovery;
    /**
     * @return The availability domain and fault domain a DB System is placed in.
     * 
     */
    private List<GetMysqlDbSystemsDbSystemCurrentPlacement> currentPlacements;
    /**
     * @return Initial size of the data volume in GiBs that will be created and attached.
     * 
     */
    private Integer dataStorageSizeInGb;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> definedTags;
    /**
     * @return The Deletion policy for the DB System.
     * 
     */
    private List<GetMysqlDbSystemsDbSystemDeletionPolicy> deletionPolicies;
    /**
     * @return User-provided data about the DB System.
     * 
     */
    private String description;
    /**
     * @return A filter to return only the resource matching the given display name exactly.
     * 
     */
    private String displayName;
    /**
     * @return The network endpoints available for this DB System.
     * 
     */
    private List<GetMysqlDbSystemsDbSystemEndpoint> endpoints;
    /**
     * @return The fault domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
     * 
     */
    private String faultDomain;
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    private Map<String,Object> freeformTags;
    /**
     * @return A summary of a HeatWave cluster.
     * 
     */
    private List<GetMysqlDbSystemsDbSystemHeatWaveCluster> heatWaveClusters;
    /**
     * @return The hostname for the primary endpoint of the DB System. Used for DNS. The value is the hostname portion of the primary private IP&#39;s fully qualified domain name (FQDN) (for example, &#34;dbsystem-1&#34; in FQDN &#34;dbsystem-1.subnet123.vcn1.oraclevcn.com&#34;). Must be unique across all VNICs in the subnet and comply with RFC 952 and RFC 1123.
     * 
     */
    private String hostnameLabel;
    /**
     * @return The OCID of the DB System.
     * 
     */
    private String id;
    /**
     * @return The IP address the DB System is configured to listen on. A private IP address of the primary endpoint of the DB System. Must be an available IP address within the subnet&#39;s CIDR. This will be a &#34;dotted-quad&#34; style IPv4 address.
     * 
     */
    private String ipAddress;
    /**
     * @return DEPRECATED -- please use HeatWave API instead. If true, return only DB Systems with an Analytics Cluster attached, if false return only DB Systems with no Analytics Cluster attached. If not present, return all DB Systems.
     * 
     */
    private Boolean isAnalyticsClusterAttached;
    /**
     * @return If true, return only DB Systems with a HeatWave cluster attached, if false return only DB Systems with no HeatWave cluster attached. If not present, return all DB Systems.
     * 
     */
    private Boolean isHeatWaveClusterAttached;
    /**
     * @return Specifies if the DB System is highly available.
     * 
     */
    private Boolean isHighlyAvailable;
    /**
     * @return Additional information about the current lifecycleState.
     * 
     */
    private String lifecycleDetails;
    /**
     * @return The Maintenance Policy for the DB System.
     * 
     */
    private List<GetMysqlDbSystemsDbSystemMaintenance> maintenances;
    /**
     * @return Name of the MySQL Version in use for the DB System.
     * 
     */
    private String mysqlVersion;
    /**
     * @return Point-in-time Recovery details like earliest and latest recovery time point for the DB System.
     * 
     */
    private List<GetMysqlDbSystemsDbSystemPointInTimeRecoveryDetail> pointInTimeRecoveryDetails;
    /**
     * @return The port for primary endpoint of the DB System to listen on.
     * 
     */
    private Integer port;
    /**
     * @return The network port on which X Plugin listens for TCP/IP connections. This is the X Plugin equivalent of port.
     * 
     */
    private Integer portX;
    /**
     * @return The shape of the primary instances of the DB System. The shape determines resources allocated to a DB System - CPU cores and memory for VM shapes; CPU cores, memory and storage for non-VM (or bare metal) shapes. To get a list of shapes, use (the [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/mysql/20181021/ShapeSummary/ListShapes) operation.
     * 
     */
    private String shapeName;
    private String shutdownType;
    /**
     * @return Parameters detailing how to provision the initial data of the DB System.
     * 
     */
    private List<GetMysqlDbSystemsDbSystemSource> sources;
    /**
     * @return DbSystem Lifecycle State
     * 
     */
    private String state;
    /**
     * @return The OCID of the subnet the DB System is associated with.
     * 
     */
    private String subnetId;
    /**
     * @return The date and time the DB System was created.
     * 
     */
    private String timeCreated;
    /**
     * @return The time the DB System was last updated.
     * 
     */
    private String timeUpdated;

    private GetMysqlDbSystemsDbSystem() {}
    public String adminPassword() {
        return this.adminPassword;
    }
    public String adminUsername() {
        return this.adminUsername;
    }
    /**
     * @return DEPRECATED -- please use HeatWave API instead. A summary of an Analytics Cluster.
     * 
     */
    public List<GetMysqlDbSystemsDbSystemAnalyticsCluster> analyticsClusters() {
        return this.analyticsClusters;
    }
    /**
     * @return The availability domain in which the DB System is placed.
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return The Backup policy for the DB System.
     * 
     */
    public List<GetMysqlDbSystemsDbSystemBackupPolicy> backupPolicies() {
        return this.backupPolicies;
    }
    /**
     * @return A list with a summary of all the Channels attached to the DB System.
     * 
     */
    public List<GetMysqlDbSystemsDbSystemChannel> channels() {
        return this.channels;
    }
    /**
     * @return The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The requested Configuration instance.
     * 
     */
    public String configurationId() {
        return this.configurationId;
    }
    /**
     * @return Whether to run the DB System with InnoDB Redo Logs and the Double Write Buffer enabled or disabled, and whether to enable or disable syncing of the Binary Logs.
     * 
     */
    public String crashRecovery() {
        return this.crashRecovery;
    }
    /**
     * @return The availability domain and fault domain a DB System is placed in.
     * 
     */
    public List<GetMysqlDbSystemsDbSystemCurrentPlacement> currentPlacements() {
        return this.currentPlacements;
    }
    /**
     * @return Initial size of the data volume in GiBs that will be created and attached.
     * 
     */
    public Integer dataStorageSizeInGb() {
        return this.dataStorageSizeInGb;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> definedTags() {
        return this.definedTags;
    }
    /**
     * @return The Deletion policy for the DB System.
     * 
     */
    public List<GetMysqlDbSystemsDbSystemDeletionPolicy> deletionPolicies() {
        return this.deletionPolicies;
    }
    /**
     * @return User-provided data about the DB System.
     * 
     */
    public String description() {
        return this.description;
    }
    /**
     * @return A filter to return only the resource matching the given display name exactly.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return The network endpoints available for this DB System.
     * 
     */
    public List<GetMysqlDbSystemsDbSystemEndpoint> endpoints() {
        return this.endpoints;
    }
    /**
     * @return The fault domain on which to deploy the Read/Write endpoint. This defines the preferred primary instance.
     * 
     */
    public String faultDomain() {
        return this.faultDomain;
    }
    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Map<String,Object> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return A summary of a HeatWave cluster.
     * 
     */
    public List<GetMysqlDbSystemsDbSystemHeatWaveCluster> heatWaveClusters() {
        return this.heatWaveClusters;
    }
    /**
     * @return The hostname for the primary endpoint of the DB System. Used for DNS. The value is the hostname portion of the primary private IP&#39;s fully qualified domain name (FQDN) (for example, &#34;dbsystem-1&#34; in FQDN &#34;dbsystem-1.subnet123.vcn1.oraclevcn.com&#34;). Must be unique across all VNICs in the subnet and comply with RFC 952 and RFC 1123.
     * 
     */
    public String hostnameLabel() {
        return this.hostnameLabel;
    }
    /**
     * @return The OCID of the DB System.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The IP address the DB System is configured to listen on. A private IP address of the primary endpoint of the DB System. Must be an available IP address within the subnet&#39;s CIDR. This will be a &#34;dotted-quad&#34; style IPv4 address.
     * 
     */
    public String ipAddress() {
        return this.ipAddress;
    }
    /**
     * @return DEPRECATED -- please use HeatWave API instead. If true, return only DB Systems with an Analytics Cluster attached, if false return only DB Systems with no Analytics Cluster attached. If not present, return all DB Systems.
     * 
     */
    public Boolean isAnalyticsClusterAttached() {
        return this.isAnalyticsClusterAttached;
    }
    /**
     * @return If true, return only DB Systems with a HeatWave cluster attached, if false return only DB Systems with no HeatWave cluster attached. If not present, return all DB Systems.
     * 
     */
    public Boolean isHeatWaveClusterAttached() {
        return this.isHeatWaveClusterAttached;
    }
    /**
     * @return Specifies if the DB System is highly available.
     * 
     */
    public Boolean isHighlyAvailable() {
        return this.isHighlyAvailable;
    }
    /**
     * @return Additional information about the current lifecycleState.
     * 
     */
    public String lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * @return The Maintenance Policy for the DB System.
     * 
     */
    public List<GetMysqlDbSystemsDbSystemMaintenance> maintenances() {
        return this.maintenances;
    }
    /**
     * @return Name of the MySQL Version in use for the DB System.
     * 
     */
    public String mysqlVersion() {
        return this.mysqlVersion;
    }
    /**
     * @return Point-in-time Recovery details like earliest and latest recovery time point for the DB System.
     * 
     */
    public List<GetMysqlDbSystemsDbSystemPointInTimeRecoveryDetail> pointInTimeRecoveryDetails() {
        return this.pointInTimeRecoveryDetails;
    }
    /**
     * @return The port for primary endpoint of the DB System to listen on.
     * 
     */
    public Integer port() {
        return this.port;
    }
    /**
     * @return The network port on which X Plugin listens for TCP/IP connections. This is the X Plugin equivalent of port.
     * 
     */
    public Integer portX() {
        return this.portX;
    }
    /**
     * @return The shape of the primary instances of the DB System. The shape determines resources allocated to a DB System - CPU cores and memory for VM shapes; CPU cores, memory and storage for non-VM (or bare metal) shapes. To get a list of shapes, use (the [ListShapes](https://docs.cloud.oracle.com/iaas/api/#/en/mysql/20181021/ShapeSummary/ListShapes) operation.
     * 
     */
    public String shapeName() {
        return this.shapeName;
    }
    public String shutdownType() {
        return this.shutdownType;
    }
    /**
     * @return Parameters detailing how to provision the initial data of the DB System.
     * 
     */
    public List<GetMysqlDbSystemsDbSystemSource> sources() {
        return this.sources;
    }
    /**
     * @return DbSystem Lifecycle State
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The OCID of the subnet the DB System is associated with.
     * 
     */
    public String subnetId() {
        return this.subnetId;
    }
    /**
     * @return The date and time the DB System was created.
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the DB System was last updated.
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMysqlDbSystemsDbSystem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String adminPassword;
        private String adminUsername;
        private List<GetMysqlDbSystemsDbSystemAnalyticsCluster> analyticsClusters;
        private String availabilityDomain;
        private List<GetMysqlDbSystemsDbSystemBackupPolicy> backupPolicies;
        private List<GetMysqlDbSystemsDbSystemChannel> channels;
        private String compartmentId;
        private String configurationId;
        private String crashRecovery;
        private List<GetMysqlDbSystemsDbSystemCurrentPlacement> currentPlacements;
        private Integer dataStorageSizeInGb;
        private Map<String,Object> definedTags;
        private List<GetMysqlDbSystemsDbSystemDeletionPolicy> deletionPolicies;
        private String description;
        private String displayName;
        private List<GetMysqlDbSystemsDbSystemEndpoint> endpoints;
        private String faultDomain;
        private Map<String,Object> freeformTags;
        private List<GetMysqlDbSystemsDbSystemHeatWaveCluster> heatWaveClusters;
        private String hostnameLabel;
        private String id;
        private String ipAddress;
        private Boolean isAnalyticsClusterAttached;
        private Boolean isHeatWaveClusterAttached;
        private Boolean isHighlyAvailable;
        private String lifecycleDetails;
        private List<GetMysqlDbSystemsDbSystemMaintenance> maintenances;
        private String mysqlVersion;
        private List<GetMysqlDbSystemsDbSystemPointInTimeRecoveryDetail> pointInTimeRecoveryDetails;
        private Integer port;
        private Integer portX;
        private String shapeName;
        private String shutdownType;
        private List<GetMysqlDbSystemsDbSystemSource> sources;
        private String state;
        private String subnetId;
        private String timeCreated;
        private String timeUpdated;
        public Builder() {}
        public Builder(GetMysqlDbSystemsDbSystem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.adminPassword = defaults.adminPassword;
    	      this.adminUsername = defaults.adminUsername;
    	      this.analyticsClusters = defaults.analyticsClusters;
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.backupPolicies = defaults.backupPolicies;
    	      this.channels = defaults.channels;
    	      this.compartmentId = defaults.compartmentId;
    	      this.configurationId = defaults.configurationId;
    	      this.crashRecovery = defaults.crashRecovery;
    	      this.currentPlacements = defaults.currentPlacements;
    	      this.dataStorageSizeInGb = defaults.dataStorageSizeInGb;
    	      this.definedTags = defaults.definedTags;
    	      this.deletionPolicies = defaults.deletionPolicies;
    	      this.description = defaults.description;
    	      this.displayName = defaults.displayName;
    	      this.endpoints = defaults.endpoints;
    	      this.faultDomain = defaults.faultDomain;
    	      this.freeformTags = defaults.freeformTags;
    	      this.heatWaveClusters = defaults.heatWaveClusters;
    	      this.hostnameLabel = defaults.hostnameLabel;
    	      this.id = defaults.id;
    	      this.ipAddress = defaults.ipAddress;
    	      this.isAnalyticsClusterAttached = defaults.isAnalyticsClusterAttached;
    	      this.isHeatWaveClusterAttached = defaults.isHeatWaveClusterAttached;
    	      this.isHighlyAvailable = defaults.isHighlyAvailable;
    	      this.lifecycleDetails = defaults.lifecycleDetails;
    	      this.maintenances = defaults.maintenances;
    	      this.mysqlVersion = defaults.mysqlVersion;
    	      this.pointInTimeRecoveryDetails = defaults.pointInTimeRecoveryDetails;
    	      this.port = defaults.port;
    	      this.portX = defaults.portX;
    	      this.shapeName = defaults.shapeName;
    	      this.shutdownType = defaults.shutdownType;
    	      this.sources = defaults.sources;
    	      this.state = defaults.state;
    	      this.subnetId = defaults.subnetId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
        }

        @CustomType.Setter
        public Builder adminPassword(String adminPassword) {
            this.adminPassword = Objects.requireNonNull(adminPassword);
            return this;
        }
        @CustomType.Setter
        public Builder adminUsername(String adminUsername) {
            this.adminUsername = Objects.requireNonNull(adminUsername);
            return this;
        }
        @CustomType.Setter
        public Builder analyticsClusters(List<GetMysqlDbSystemsDbSystemAnalyticsCluster> analyticsClusters) {
            this.analyticsClusters = Objects.requireNonNull(analyticsClusters);
            return this;
        }
        public Builder analyticsClusters(GetMysqlDbSystemsDbSystemAnalyticsCluster... analyticsClusters) {
            return analyticsClusters(List.of(analyticsClusters));
        }
        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            this.availabilityDomain = Objects.requireNonNull(availabilityDomain);
            return this;
        }
        @CustomType.Setter
        public Builder backupPolicies(List<GetMysqlDbSystemsDbSystemBackupPolicy> backupPolicies) {
            this.backupPolicies = Objects.requireNonNull(backupPolicies);
            return this;
        }
        public Builder backupPolicies(GetMysqlDbSystemsDbSystemBackupPolicy... backupPolicies) {
            return backupPolicies(List.of(backupPolicies));
        }
        @CustomType.Setter
        public Builder channels(List<GetMysqlDbSystemsDbSystemChannel> channels) {
            this.channels = Objects.requireNonNull(channels);
            return this;
        }
        public Builder channels(GetMysqlDbSystemsDbSystemChannel... channels) {
            return channels(List.of(channels));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder configurationId(String configurationId) {
            this.configurationId = Objects.requireNonNull(configurationId);
            return this;
        }
        @CustomType.Setter
        public Builder crashRecovery(String crashRecovery) {
            this.crashRecovery = Objects.requireNonNull(crashRecovery);
            return this;
        }
        @CustomType.Setter
        public Builder currentPlacements(List<GetMysqlDbSystemsDbSystemCurrentPlacement> currentPlacements) {
            this.currentPlacements = Objects.requireNonNull(currentPlacements);
            return this;
        }
        public Builder currentPlacements(GetMysqlDbSystemsDbSystemCurrentPlacement... currentPlacements) {
            return currentPlacements(List.of(currentPlacements));
        }
        @CustomType.Setter
        public Builder dataStorageSizeInGb(Integer dataStorageSizeInGb) {
            this.dataStorageSizeInGb = Objects.requireNonNull(dataStorageSizeInGb);
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,Object> definedTags) {
            this.definedTags = Objects.requireNonNull(definedTags);
            return this;
        }
        @CustomType.Setter
        public Builder deletionPolicies(List<GetMysqlDbSystemsDbSystemDeletionPolicy> deletionPolicies) {
            this.deletionPolicies = Objects.requireNonNull(deletionPolicies);
            return this;
        }
        public Builder deletionPolicies(GetMysqlDbSystemsDbSystemDeletionPolicy... deletionPolicies) {
            return deletionPolicies(List.of(deletionPolicies));
        }
        @CustomType.Setter
        public Builder description(String description) {
            this.description = Objects.requireNonNull(description);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder endpoints(List<GetMysqlDbSystemsDbSystemEndpoint> endpoints) {
            this.endpoints = Objects.requireNonNull(endpoints);
            return this;
        }
        public Builder endpoints(GetMysqlDbSystemsDbSystemEndpoint... endpoints) {
            return endpoints(List.of(endpoints));
        }
        @CustomType.Setter
        public Builder faultDomain(String faultDomain) {
            this.faultDomain = Objects.requireNonNull(faultDomain);
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,Object> freeformTags) {
            this.freeformTags = Objects.requireNonNull(freeformTags);
            return this;
        }
        @CustomType.Setter
        public Builder heatWaveClusters(List<GetMysqlDbSystemsDbSystemHeatWaveCluster> heatWaveClusters) {
            this.heatWaveClusters = Objects.requireNonNull(heatWaveClusters);
            return this;
        }
        public Builder heatWaveClusters(GetMysqlDbSystemsDbSystemHeatWaveCluster... heatWaveClusters) {
            return heatWaveClusters(List.of(heatWaveClusters));
        }
        @CustomType.Setter
        public Builder hostnameLabel(String hostnameLabel) {
            this.hostnameLabel = Objects.requireNonNull(hostnameLabel);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder ipAddress(String ipAddress) {
            this.ipAddress = Objects.requireNonNull(ipAddress);
            return this;
        }
        @CustomType.Setter
        public Builder isAnalyticsClusterAttached(Boolean isAnalyticsClusterAttached) {
            this.isAnalyticsClusterAttached = Objects.requireNonNull(isAnalyticsClusterAttached);
            return this;
        }
        @CustomType.Setter
        public Builder isHeatWaveClusterAttached(Boolean isHeatWaveClusterAttached) {
            this.isHeatWaveClusterAttached = Objects.requireNonNull(isHeatWaveClusterAttached);
            return this;
        }
        @CustomType.Setter
        public Builder isHighlyAvailable(Boolean isHighlyAvailable) {
            this.isHighlyAvailable = Objects.requireNonNull(isHighlyAvailable);
            return this;
        }
        @CustomType.Setter
        public Builder lifecycleDetails(String lifecycleDetails) {
            this.lifecycleDetails = Objects.requireNonNull(lifecycleDetails);
            return this;
        }
        @CustomType.Setter
        public Builder maintenances(List<GetMysqlDbSystemsDbSystemMaintenance> maintenances) {
            this.maintenances = Objects.requireNonNull(maintenances);
            return this;
        }
        public Builder maintenances(GetMysqlDbSystemsDbSystemMaintenance... maintenances) {
            return maintenances(List.of(maintenances));
        }
        @CustomType.Setter
        public Builder mysqlVersion(String mysqlVersion) {
            this.mysqlVersion = Objects.requireNonNull(mysqlVersion);
            return this;
        }
        @CustomType.Setter
        public Builder pointInTimeRecoveryDetails(List<GetMysqlDbSystemsDbSystemPointInTimeRecoveryDetail> pointInTimeRecoveryDetails) {
            this.pointInTimeRecoveryDetails = Objects.requireNonNull(pointInTimeRecoveryDetails);
            return this;
        }
        public Builder pointInTimeRecoveryDetails(GetMysqlDbSystemsDbSystemPointInTimeRecoveryDetail... pointInTimeRecoveryDetails) {
            return pointInTimeRecoveryDetails(List.of(pointInTimeRecoveryDetails));
        }
        @CustomType.Setter
        public Builder port(Integer port) {
            this.port = Objects.requireNonNull(port);
            return this;
        }
        @CustomType.Setter
        public Builder portX(Integer portX) {
            this.portX = Objects.requireNonNull(portX);
            return this;
        }
        @CustomType.Setter
        public Builder shapeName(String shapeName) {
            this.shapeName = Objects.requireNonNull(shapeName);
            return this;
        }
        @CustomType.Setter
        public Builder shutdownType(String shutdownType) {
            this.shutdownType = Objects.requireNonNull(shutdownType);
            return this;
        }
        @CustomType.Setter
        public Builder sources(List<GetMysqlDbSystemsDbSystemSource> sources) {
            this.sources = Objects.requireNonNull(sources);
            return this;
        }
        public Builder sources(GetMysqlDbSystemsDbSystemSource... sources) {
            return sources(List.of(sources));
        }
        @CustomType.Setter
        public Builder state(String state) {
            this.state = Objects.requireNonNull(state);
            return this;
        }
        @CustomType.Setter
        public Builder subnetId(String subnetId) {
            this.subnetId = Objects.requireNonNull(subnetId);
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            this.timeUpdated = Objects.requireNonNull(timeUpdated);
            return this;
        }
        public GetMysqlDbSystemsDbSystem build() {
            final var o = new GetMysqlDbSystemsDbSystem();
            o.adminPassword = adminPassword;
            o.adminUsername = adminUsername;
            o.analyticsClusters = analyticsClusters;
            o.availabilityDomain = availabilityDomain;
            o.backupPolicies = backupPolicies;
            o.channels = channels;
            o.compartmentId = compartmentId;
            o.configurationId = configurationId;
            o.crashRecovery = crashRecovery;
            o.currentPlacements = currentPlacements;
            o.dataStorageSizeInGb = dataStorageSizeInGb;
            o.definedTags = definedTags;
            o.deletionPolicies = deletionPolicies;
            o.description = description;
            o.displayName = displayName;
            o.endpoints = endpoints;
            o.faultDomain = faultDomain;
            o.freeformTags = freeformTags;
            o.heatWaveClusters = heatWaveClusters;
            o.hostnameLabel = hostnameLabel;
            o.id = id;
            o.ipAddress = ipAddress;
            o.isAnalyticsClusterAttached = isAnalyticsClusterAttached;
            o.isHeatWaveClusterAttached = isHeatWaveClusterAttached;
            o.isHighlyAvailable = isHighlyAvailable;
            o.lifecycleDetails = lifecycleDetails;
            o.maintenances = maintenances;
            o.mysqlVersion = mysqlVersion;
            o.pointInTimeRecoveryDetails = pointInTimeRecoveryDetails;
            o.port = port;
            o.portX = portX;
            o.shapeName = shapeName;
            o.shutdownType = shutdownType;
            o.sources = sources;
            o.state = state;
            o.subnetId = subnetId;
            o.timeCreated = timeCreated;
            o.timeUpdated = timeUpdated;
            return o;
        }
    }
}