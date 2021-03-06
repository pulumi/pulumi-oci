// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Database.CloudVmClusterArgs;
import com.pulumi.oci.Database.inputs.CloudVmClusterState;
import com.pulumi.oci.Database.outputs.CloudVmClusterIormConfigCach;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Cloud Vm Cluster resource in Oracle Cloud Infrastructure Database service.
 * 
 * Creates a cloud VM cluster.
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * CloudVmClusters can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Database/cloudVmCluster:CloudVmCluster test_cloud_vm_cluster &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Database/cloudVmCluster:CloudVmCluster")
public class CloudVmCluster extends com.pulumi.resources.CustomResource {
    /**
     * The name of the availability domain that the cloud Exadata infrastructure resource is located in.
     * 
     */
    @Export(name="availabilityDomain", type=String.class, parameters={})
    private Output<String> availabilityDomain;

    /**
     * @return The name of the availability domain that the cloud Exadata infrastructure resource is located in.
     * 
     */
    public Output<String> availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * (Updatable) A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that the backup network of this DB system belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). Applicable only to Exadata systems.
     * 
     */
    @Export(name="backupNetworkNsgIds", type=List.class, parameters={String.class})
    private Output<List<String>> backupNetworkNsgIds;

    /**
     * @return (Updatable) A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that the backup network of this DB system belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). Applicable only to Exadata systems.
     * 
     */
    public Output<List<String>> backupNetworkNsgIds() {
        return this.backupNetworkNsgIds;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup network subnet associated with the cloud VM cluster.
     * 
     */
    @Export(name="backupSubnetId", type=String.class, parameters={})
    private Output<String> backupSubnetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup network subnet associated with the cloud VM cluster.
     * 
     */
    public Output<String> backupSubnetId() {
        return this.backupSubnetId;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure resource.
     * 
     */
    @Export(name="cloudExadataInfrastructureId", type=String.class, parameters={})
    private Output<String> cloudExadataInfrastructureId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure resource.
     * 
     */
    public Output<String> cloudExadataInfrastructureId() {
        return this.cloudExadataInfrastructureId;
    }
    /**
     * The cluster name for cloud VM cluster. The cluster name must begin with an alphabetic character, and may contain hyphens (-). Underscores (_) are not permitted. The cluster name can be no longer than 11 characters and is not case sensitive.
     * 
     */
    @Export(name="clusterName", type=String.class, parameters={})
    private Output<String> clusterName;

    /**
     * @return The cluster name for cloud VM cluster. The cluster name must begin with an alphabetic character, and may contain hyphens (-). Underscores (_) are not permitted. The cluster name can be no longer than 11 characters and is not case sensitive.
     * 
     */
    public Output<String> clusterName() {
        return this.clusterName;
    }
    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) The number of CPU cores to enable for a cloud VM cluster. Valid values depend on the specified shape:
     * * Exadata.Base.48 - Specify a multiple of 2, from 0 to 48.
     * * Exadata.Quarter1.84 - Specify a multiple of 2, from 22 to 84.
     * * Exadata.Half1.168 - Specify a multiple of 4, from 44 to 168.
     * * Exadata.Full1.336 - Specify a multiple of 8, from 88 to 336.
     * * Exadata.Quarter2.92 - Specify a multiple of 2, from 0 to 92.
     * * Exadata.Half2.184 - Specify a multiple of 4, from 0 to 184.
     * * Exadata.Full2.368 - Specify a multiple of 8, from 0 to 368.
     * 
     */
    @Export(name="cpuCoreCount", type=Integer.class, parameters={})
    private Output<Integer> cpuCoreCount;

    /**
     * @return (Updatable) The number of CPU cores to enable for a cloud VM cluster. Valid values depend on the specified shape:
     * * Exadata.Base.48 - Specify a multiple of 2, from 0 to 48.
     * * Exadata.Quarter1.84 - Specify a multiple of 2, from 22 to 84.
     * * Exadata.Half1.168 - Specify a multiple of 4, from 44 to 168.
     * * Exadata.Full1.336 - Specify a multiple of 8, from 88 to 336.
     * * Exadata.Quarter2.92 - Specify a multiple of 2, from 0 to 92.
     * * Exadata.Half2.184 - Specify a multiple of 4, from 0 to 184.
     * * Exadata.Full2.368 - Specify a multiple of 8, from 0 to 368.
     * 
     */
    public Output<Integer> cpuCoreCount() {
        return this.cpuCoreCount;
    }
    @Export(name="createAsync", type=Boolean.class, parameters={})
    private Output</* @Nullable */ Boolean> createAsync;

    public Output<Optional<Boolean>> createAsync() {
        return Codegen.optional(this.createAsync);
    }
    /**
     * The percentage assigned to DATA storage (user data and database files). The remaining percentage is assigned to RECO storage (database redo logs, archive logs, and recovery manager backups). Accepted values are 35, 40, 60 and 80. The default is 80 percent assigned to DATA storage. See [Storage Configuration](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/exaoverview.htm#Exadata) in the Exadata documentation for details on the impact of the configuration settings on storage.
     * 
     */
    @Export(name="dataStoragePercentage", type=Integer.class, parameters={})
    private Output<Integer> dataStoragePercentage;

    /**
     * @return The percentage assigned to DATA storage (user data and database files). The remaining percentage is assigned to RECO storage (database redo logs, archive logs, and recovery manager backups). Accepted values are 35, 40, 60 and 80. The default is 80 percent assigned to DATA storage. See [Storage Configuration](https://docs.cloud.oracle.com/iaas/Content/Database/Concepts/exaoverview.htm#Exadata) in the Exadata documentation for details on the impact of the configuration settings on storage.
     * 
     */
    public Output<Integer> dataStoragePercentage() {
        return this.dataStoragePercentage;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * The type of redundancy configured for the cloud Vm cluster. NORMAL is 2-way redundancy. HIGH is 3-way redundancy.
     * 
     */
    @Export(name="diskRedundancy", type=String.class, parameters={})
    private Output<String> diskRedundancy;

    /**
     * @return The type of redundancy configured for the cloud Vm cluster. NORMAL is 2-way redundancy. HIGH is 3-way redundancy.
     * 
     */
    public Output<String> diskRedundancy() {
        return this.diskRedundancy;
    }
    /**
     * (Updatable) The user-friendly name for the cloud VM cluster. The name does not need to be unique.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) The user-friendly name for the cloud VM cluster. The name does not need to be unique.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * A domain name used for the cloud VM cluster. If the Oracle-provided internet and VCN resolver is enabled for the specified subnet, the domain name for the subnet is used (do not provide one). Otherwise, provide a valid DNS domain name. Hyphens (-) are not permitted. Applies to Exadata Cloud Service instances only.
     * 
     */
    @Export(name="domain", type=String.class, parameters={})
    private Output<String> domain;

    /**
     * @return A domain name used for the cloud VM cluster. If the Oracle-provided internet and VCN resolver is enabled for the specified subnet, the domain name for the subnet is used (do not provide one). Otherwise, provide a valid DNS domain name. Hyphens (-) are not permitted. Applies to Exadata Cloud Service instances only.
     * 
     */
    public Output<String> domain() {
        return this.domain;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * A valid Oracle Grid Infrastructure (GI) software version.
     * 
     */
    @Export(name="giVersion", type=String.class, parameters={})
    private Output<String> giVersion;

    /**
     * @return A valid Oracle Grid Infrastructure (GI) software version.
     * 
     */
    public Output<String> giVersion() {
        return this.giVersion;
    }
    /**
     * The hostname for the cloud VM cluster. The hostname must begin with an alphabetic character, and can contain alphanumeric characters and hyphens (-). The maximum length of the hostname is 16 characters for bare metal and virtual machine DB systems, and 12 characters for Exadata systems.
     * 
     */
    @Export(name="hostname", type=String.class, parameters={})
    private Output<String> hostname;

    /**
     * @return The hostname for the cloud VM cluster. The hostname must begin with an alphabetic character, and can contain alphanumeric characters and hyphens (-). The maximum length of the hostname is 16 characters for bare metal and virtual machine DB systems, and 12 characters for Exadata systems.
     * 
     */
    public Output<String> hostname() {
        return this.hostname;
    }
    /**
     * The IORM settings of the Exadata DB system.
     * 
     */
    @Export(name="iormConfigCaches", type=List.class, parameters={CloudVmClusterIormConfigCach.class})
    private Output<List<CloudVmClusterIormConfigCach>> iormConfigCaches;

    /**
     * @return The IORM settings of the Exadata DB system.
     * 
     */
    public Output<List<CloudVmClusterIormConfigCach>> iormConfigCaches() {
        return this.iormConfigCaches;
    }
    /**
     * If true, database backup on local Exadata storage is configured for the cloud VM cluster. If false, database backup on local Exadata storage is not available in the cloud VM cluster.
     * 
     */
    @Export(name="isLocalBackupEnabled", type=Boolean.class, parameters={})
    private Output<Boolean> isLocalBackupEnabled;

    /**
     * @return If true, database backup on local Exadata storage is configured for the cloud VM cluster. If false, database backup on local Exadata storage is not available in the cloud VM cluster.
     * 
     */
    public Output<Boolean> isLocalBackupEnabled() {
        return this.isLocalBackupEnabled;
    }
    /**
     * If true, the sparse disk group is configured for the cloud VM cluster. If false, the sparse disk group is not created.
     * 
     */
    @Export(name="isSparseDiskgroupEnabled", type=Boolean.class, parameters={})
    private Output<Boolean> isSparseDiskgroupEnabled;

    /**
     * @return If true, the sparse disk group is configured for the cloud VM cluster. If false, the sparse disk group is not created.
     * 
     */
    public Output<Boolean> isSparseDiskgroupEnabled() {
        return this.isSparseDiskgroupEnabled;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance update history entry. This value is updated when a maintenance update starts.
     * 
     */
    @Export(name="lastUpdateHistoryEntryId", type=String.class, parameters={})
    private Output<String> lastUpdateHistoryEntryId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last maintenance update history entry. This value is updated when a maintenance update starts.
     * 
     */
    public Output<String> lastUpdateHistoryEntryId() {
        return this.lastUpdateHistoryEntryId;
    }
    /**
     * (Updatable) The Oracle license model that applies to the cloud VM cluster. The default is BRING_YOUR_OWN_LICENSE.
     * 
     */
    @Export(name="licenseModel", type=String.class, parameters={})
    private Output<String> licenseModel;

    /**
     * @return (Updatable) The Oracle license model that applies to the cloud VM cluster. The default is BRING_YOUR_OWN_LICENSE.
     * 
     */
    public Output<String> licenseModel() {
        return this.licenseModel;
    }
    /**
     * Additional information about the current lifecycle state.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return Additional information about the current lifecycle state.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The port number configured for the listener on the cloud VM cluster.
     * 
     */
    @Export(name="listenerPort", type=String.class, parameters={})
    private Output<String> listenerPort;

    /**
     * @return The port number configured for the listener on the cloud VM cluster.
     * 
     */
    public Output<String> listenerPort() {
        return this.listenerPort;
    }
    /**
     * The number of nodes in the cloud VM cluster.
     * 
     */
    @Export(name="nodeCount", type=Integer.class, parameters={})
    private Output<Integer> nodeCount;

    /**
     * @return The number of nodes in the cloud VM cluster.
     * 
     */
    public Output<Integer> nodeCount() {
        return this.nodeCount;
    }
    /**
     * (Updatable) A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that this resource belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). **NsgIds restrictions:**
     * * Autonomous Databases with private access require at least 1 Network Security Group (NSG). The nsgIds array cannot be empty.
     * 
     */
    @Export(name="nsgIds", type=List.class, parameters={String.class})
    private Output<List<String>> nsgIds;

    /**
     * @return (Updatable) A list of the [OCIDs](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network security groups (NSGs) that this resource belongs to. Setting this to an empty array after the list is created removes the resource from all NSGs. For more information about NSGs, see [Security Rules](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/securityrules.htm). **NsgIds restrictions:**
     * * Autonomous Databases with private access require at least 1 Network Security Group (NSG). The nsgIds array cannot be empty.
     * 
     */
    public Output<List<String>> nsgIds() {
        return this.nsgIds;
    }
    /**
     * (Updatable) The number of OCPU cores to enable for a cloud VM cluster. Only 1 decimal place is allowed for the fractional part.
     * 
     */
    @Export(name="ocpuCount", type=Double.class, parameters={})
    private Output<Double> ocpuCount;

    /**
     * @return (Updatable) The number of OCPU cores to enable for a cloud VM cluster. Only 1 decimal place is allowed for the fractional part.
     * 
     */
    public Output<Double> ocpuCount() {
        return this.ocpuCount;
    }
    /**
     * The FQDN of the DNS record for the SCAN IP addresses that are associated with the cloud VM cluster.
     * 
     */
    @Export(name="scanDnsName", type=String.class, parameters={})
    private Output<String> scanDnsName;

    /**
     * @return The FQDN of the DNS record for the SCAN IP addresses that are associated with the cloud VM cluster.
     * 
     */
    public Output<String> scanDnsName() {
        return this.scanDnsName;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DNS record for the SCAN IP addresses that are associated with the cloud VM cluster.
     * 
     */
    @Export(name="scanDnsRecordId", type=String.class, parameters={})
    private Output<String> scanDnsRecordId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DNS record for the SCAN IP addresses that are associated with the cloud VM cluster.
     * 
     */
    public Output<String> scanDnsRecordId() {
        return this.scanDnsRecordId;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Single Client Access Name (SCAN) IP addresses associated with the cloud VM cluster. SCAN IP addresses are typically used for load balancing and are not assigned to any interface. Oracle Clusterware directs the requests to the appropriate nodes in the cluster.
     * 
     */
    @Export(name="scanIpIds", type=List.class, parameters={String.class})
    private Output<List<String>> scanIpIds;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Single Client Access Name (SCAN) IP addresses associated with the cloud VM cluster. SCAN IP addresses are typically used for load balancing and are not assigned to any interface. Oracle Clusterware directs the requests to the appropriate nodes in the cluster.
     * 
     */
    public Output<List<String>> scanIpIds() {
        return this.scanIpIds;
    }
    /**
     * The TCP Single Client Access Name (SCAN) port. The default port is 1521.
     * 
     */
    @Export(name="scanListenerPortTcp", type=Integer.class, parameters={})
    private Output<Integer> scanListenerPortTcp;

    /**
     * @return The TCP Single Client Access Name (SCAN) port. The default port is 1521.
     * 
     */
    public Output<Integer> scanListenerPortTcp() {
        return this.scanListenerPortTcp;
    }
    /**
     * The TCPS Single Client Access Name (SCAN) port. The default port is 2484.
     * 
     */
    @Export(name="scanListenerPortTcpSsl", type=Integer.class, parameters={})
    private Output<Integer> scanListenerPortTcpSsl;

    /**
     * @return The TCPS Single Client Access Name (SCAN) port. The default port is 2484.
     * 
     */
    public Output<Integer> scanListenerPortTcpSsl() {
        return this.scanListenerPortTcpSsl;
    }
    /**
     * The model name of the Exadata hardware running the cloud VM cluster.
     * 
     */
    @Export(name="shape", type=String.class, parameters={})
    private Output<String> shape;

    /**
     * @return The model name of the Exadata hardware running the cloud VM cluster.
     * 
     */
    public Output<String> shape() {
        return this.shape;
    }
    /**
     * (Updatable) The public key portion of one or more key pairs used for SSH access to the cloud VM cluster.
     * 
     */
    @Export(name="sshPublicKeys", type=List.class, parameters={String.class})
    private Output<List<String>> sshPublicKeys;

    /**
     * @return (Updatable) The public key portion of one or more key pairs used for SSH access to the cloud VM cluster.
     * 
     */
    public Output<List<String>> sshPublicKeys() {
        return this.sshPublicKeys;
    }
    /**
     * The current state of the cloud VM cluster.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the cloud VM cluster.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * The storage allocation for the disk group, in gigabytes (GB).
     * 
     */
    @Export(name="storageSizeInGbs", type=Integer.class, parameters={})
    private Output<Integer> storageSizeInGbs;

    /**
     * @return The storage allocation for the disk group, in gigabytes (GB).
     * 
     */
    public Output<Integer> storageSizeInGbs() {
        return this.storageSizeInGbs;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet associated with the cloud VM cluster.
     * 
     */
    @Export(name="subnetId", type=String.class, parameters={})
    private Output<String> subnetId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet associated with the cloud VM cluster.
     * 
     */
    public Output<String> subnetId() {
        return this.subnetId;
    }
    /**
     * Operating system version of the image.
     * 
     */
    @Export(name="systemVersion", type=String.class, parameters={})
    private Output<String> systemVersion;

    /**
     * @return Operating system version of the image.
     * 
     */
    public Output<String> systemVersion() {
        return this.systemVersion;
    }
    /**
     * The date and time that the cloud VM cluster was created.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time that the cloud VM cluster was created.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time zone to use for the cloud VM cluster. For details, see [Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
     * 
     */
    @Export(name="timeZone", type=String.class, parameters={})
    private Output<String> timeZone;

    /**
     * @return The time zone to use for the cloud VM cluster. For details, see [Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
     * 
     */
    public Output<String> timeZone() {
        return this.timeZone;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual IP (VIP) addresses associated with the cloud VM cluster. The Cluster Ready Services (CRS) creates and maintains one VIP address for each node in the Exadata Cloud Service instance to enable failover. If one node fails, the VIP is reassigned to another active node in the cluster.
     * 
     */
    @Export(name="vipIds", type=List.class, parameters={String.class})
    private Output<List<String>> vipIds;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual IP (VIP) addresses associated with the cloud VM cluster. The Cluster Ready Services (CRS) creates and maintains one VIP address for each node in the Exadata Cloud Service instance to enable failover. If one node fails, the VIP is reassigned to another active node in the cluster.
     * 
     */
    public Output<List<String>> vipIds() {
        return this.vipIds;
    }
    /**
     * The OCID of the zone the cloud VM cluster is associated with.
     * 
     */
    @Export(name="zoneId", type=String.class, parameters={})
    private Output<String> zoneId;

    /**
     * @return The OCID of the zone the cloud VM cluster is associated with.
     * 
     */
    public Output<String> zoneId() {
        return this.zoneId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public CloudVmCluster(String name) {
        this(name, CloudVmClusterArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public CloudVmCluster(String name, CloudVmClusterArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public CloudVmCluster(String name, CloudVmClusterArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/cloudVmCluster:CloudVmCluster", name, args == null ? CloudVmClusterArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private CloudVmCluster(String name, Output<String> id, @Nullable CloudVmClusterState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/cloudVmCluster:CloudVmCluster", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static CloudVmCluster get(String name, Output<String> id, @Nullable CloudVmClusterState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new CloudVmCluster(name, id, state, options);
    }
}
