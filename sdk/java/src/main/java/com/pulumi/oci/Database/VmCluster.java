// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Database.VmClusterArgs;
import com.pulumi.oci.Database.inputs.VmClusterState;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Double;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Vm Cluster resource in Oracle Cloud Infrastructure Database service.
 * 
 * Creates an Exadata Cloud@Customer VM cluster.
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * VmClusters can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Database/vmCluster:VmCluster test_vm_cluster &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Database/vmCluster:VmCluster")
public class VmCluster extends com.pulumi.resources.CustomResource {
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
    @Export(name="cpuCoreCount", type=Integer.class, parameters={})
    private Output<Integer> cpuCoreCount;

    public Output<Integer> cpuCoreCount() {
        return this.cpuCoreCount;
    }
    /**
     * The number of enabled CPU cores.
     * 
     */
    @Export(name="cpusEnabled", type=Integer.class, parameters={})
    private Output<Integer> cpusEnabled;

    /**
     * @return The number of enabled CPU cores.
     * 
     */
    public Output<Integer> cpusEnabled() {
        return this.cpusEnabled;
    }
    @Export(name="dataStorageSizeInGb", type=Double.class, parameters={})
    private Output<Double> dataStorageSizeInGb;

    public Output<Double> dataStorageSizeInGb() {
        return this.dataStorageSizeInGb;
    }
    /**
     * (Updatable) The data disk group size to be allocated in TBs.
     * 
     */
    @Export(name="dataStorageSizeInTbs", type=Double.class, parameters={})
    private Output<Double> dataStorageSizeInTbs;

    /**
     * @return (Updatable) The data disk group size to be allocated in TBs.
     * 
     */
    public Output<Double> dataStorageSizeInTbs() {
        return this.dataStorageSizeInTbs;
    }
    /**
     * (Updatable) The local node storage to be allocated in GBs.
     * 
     */
    @Export(name="dbNodeStorageSizeInGbs", type=Integer.class, parameters={})
    private Output<Integer> dbNodeStorageSizeInGbs;

    /**
     * @return (Updatable) The local node storage to be allocated in GBs.
     * 
     */
    public Output<Integer> dbNodeStorageSizeInGbs() {
        return this.dbNodeStorageSizeInGbs;
    }
    /**
     * The list of Db server.
     * 
     */
    @Export(name="dbServers", type=List.class, parameters={String.class})
    private Output<List<String>> dbServers;

    /**
     * @return The list of Db server.
     * 
     */
    public Output<List<String>> dbServers() {
        return this.dbServers;
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
     * The user-friendly name for the VM cluster. The name does not need to be unique.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return The user-friendly name for the VM cluster. The name does not need to be unique.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     * 
     */
    @Export(name="exadataInfrastructureId", type=String.class, parameters={})
    private Output<String> exadataInfrastructureId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     * 
     */
    public Output<String> exadataInfrastructureId() {
        return this.exadataInfrastructureId;
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
     * The Oracle Grid Infrastructure software version for the VM cluster.
     * 
     */
    @Export(name="giVersion", type=String.class, parameters={})
    private Output<String> giVersion;

    /**
     * @return The Oracle Grid Infrastructure software version for the VM cluster.
     * 
     */
    public Output<String> giVersion() {
        return this.giVersion;
    }
    /**
     * If true, database backup on local Exadata storage is configured for the VM cluster. If false, database backup on local Exadata storage is not available in the VM cluster.
     * 
     */
    @Export(name="isLocalBackupEnabled", type=Boolean.class, parameters={})
    private Output<Boolean> isLocalBackupEnabled;

    /**
     * @return If true, database backup on local Exadata storage is configured for the VM cluster. If false, database backup on local Exadata storage is not available in the VM cluster.
     * 
     */
    public Output<Boolean> isLocalBackupEnabled() {
        return this.isLocalBackupEnabled;
    }
    /**
     * If true, the sparse disk group is configured for the VM cluster. If false, the sparse disk group is not created.
     * 
     */
    @Export(name="isSparseDiskgroupEnabled", type=Boolean.class, parameters={})
    private Output<Boolean> isSparseDiskgroupEnabled;

    /**
     * @return If true, the sparse disk group is configured for the VM cluster. If false, the sparse disk group is not created.
     * 
     */
    public Output<Boolean> isSparseDiskgroupEnabled() {
        return this.isSparseDiskgroupEnabled;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch history. This value is updated as soon as a patch operation starts.
     * 
     */
    @Export(name="lastPatchHistoryEntryId", type=String.class, parameters={})
    private Output<String> lastPatchHistoryEntryId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch history. This value is updated as soon as a patch operation starts.
     * 
     */
    public Output<String> lastPatchHistoryEntryId() {
        return this.lastPatchHistoryEntryId;
    }
    /**
     * (Updatable) The Oracle license model that applies to the VM cluster. The default is BRING_YOUR_OWN_LICENSE.
     * 
     */
    @Export(name="licenseModel", type=String.class, parameters={})
    private Output<String> licenseModel;

    /**
     * @return (Updatable) The Oracle license model that applies to the VM cluster. The default is BRING_YOUR_OWN_LICENSE.
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
     * (Updatable) The memory to be allocated in GBs.
     * 
     */
    @Export(name="memorySizeInGbs", type=Integer.class, parameters={})
    private Output<Integer> memorySizeInGbs;

    /**
     * @return (Updatable) The memory to be allocated in GBs.
     * 
     */
    public Output<Integer> memorySizeInGbs() {
        return this.memorySizeInGbs;
    }
    @Export(name="ocpuCount", type=Double.class, parameters={})
    private Output<Double> ocpuCount;

    public Output<Double> ocpuCount() {
        return this.ocpuCount;
    }
    @Export(name="ocpusEnabled", type=Double.class, parameters={})
    private Output<Double> ocpusEnabled;

    public Output<Double> ocpusEnabled() {
        return this.ocpusEnabled;
    }
    /**
     * The shape of the Exadata infrastructure. The shape determines the amount of CPU, storage, and memory resources allocated to the instance.
     * 
     */
    @Export(name="shape", type=String.class, parameters={})
    private Output<String> shape;

    /**
     * @return The shape of the Exadata infrastructure. The shape determines the amount of CPU, storage, and memory resources allocated to the instance.
     * 
     */
    public Output<String> shape() {
        return this.shape;
    }
    /**
     * (Updatable) The public key portion of one or more key pairs used for SSH access to the VM cluster.
     * 
     */
    @Export(name="sshPublicKeys", type=List.class, parameters={String.class})
    private Output<List<String>> sshPublicKeys;

    /**
     * @return (Updatable) The public key portion of one or more key pairs used for SSH access to the VM cluster.
     * 
     */
    public Output<List<String>> sshPublicKeys() {
        return this.sshPublicKeys;
    }
    /**
     * The current state of the VM cluster.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the VM cluster.
     * 
     */
    public Output<String> state() {
        return this.state;
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
     * The date and time that the VM cluster was created.
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time that the VM cluster was created.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time zone to use for the VM cluster. For details, see [DB System Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
     * 
     */
    @Export(name="timeZone", type=String.class, parameters={})
    private Output<String> timeZone;

    /**
     * @return The time zone to use for the VM cluster. For details, see [DB System Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
     * 
     */
    public Output<String> timeZone() {
        return this.timeZone;
    }
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
     * 
     */
    @Export(name="vmClusterNetworkId", type=String.class, parameters={})
    private Output<String> vmClusterNetworkId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
     * 
     */
    public Output<String> vmClusterNetworkId() {
        return this.vmClusterNetworkId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public VmCluster(String name) {
        this(name, VmClusterArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public VmCluster(String name, VmClusterArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public VmCluster(String name, VmClusterArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/vmCluster:VmCluster", name, args == null ? VmClusterArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private VmCluster(String name, Output<String> id, @Nullable VmClusterState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Database/vmCluster:VmCluster", name, state, makeResourceOptions(options, id));
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
    public static VmCluster get(String name, Output<String> id, @Nullable VmClusterState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new VmCluster(name, id, state, options);
    }
}
