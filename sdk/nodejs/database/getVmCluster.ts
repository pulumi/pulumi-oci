// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Vm Cluster resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets information about the VM cluster. Applies to Exadata Cloud@Customer instances only.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVmCluster = oci.Database.getVmCluster({
 *     vmClusterId: oci_database_vm_cluster.test_vm_cluster.id,
 * });
 * ```
 */
export function getVmCluster(args: GetVmClusterArgs, opts?: pulumi.InvokeOptions): Promise<GetVmClusterResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Database/getVmCluster:getVmCluster", {
        "vmClusterId": args.vmClusterId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVmCluster.
 */
export interface GetVmClusterArgs {
    /**
     * The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    vmClusterId: string;
}

/**
 * A collection of values returned by getVmCluster.
 */
export interface GetVmClusterResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    readonly cpuCoreCount: number;
    /**
     * The number of enabled CPU cores.
     */
    readonly cpusEnabled: number;
    /**
     * Indicates user preferences for the various diagnostic collection options for the VM cluster/Cloud VM cluster/VMBM DBCS.
     */
    readonly dataCollectionOptions: outputs.Database.GetVmClusterDataCollectionOption[];
    /**
     * Size of the DATA disk group in GBs.
     */
    readonly dataStorageSizeInGb: number;
    /**
     * Size, in terabytes, of the DATA disk group.
     */
    readonly dataStorageSizeInTbs: number;
    /**
     * The local node storage allocated in GBs.
     */
    readonly dbNodeStorageSizeInGbs: number;
    /**
     * The list of Db server.
     */
    readonly dbServers: string[];
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    readonly definedTags: {[key: string]: any};
    /**
     * The user-friendly name for the Exadata Cloud@Customer VM cluster. The name does not need to be unique.
     */
    readonly displayName: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata infrastructure.
     */
    readonly exadataInfrastructureId: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The Oracle Grid Infrastructure software version for the VM cluster.
     */
    readonly giVersion: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster.
     */
    readonly id: string;
    /**
     * If true, database backup on local Exadata storage is configured for the VM cluster. If false, database backup on local Exadata storage is not available in the VM cluster.
     */
    readonly isLocalBackupEnabled: boolean;
    /**
     * If true, sparse disk group is configured for the VM cluster. If false, sparse disk group is not created.
     */
    readonly isSparseDiskgroupEnabled: boolean;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch history. This value is updated as soon as a patch operation starts.
     */
    readonly lastPatchHistoryEntryId: string;
    /**
     * The Oracle license model that applies to the VM cluster. The default is LICENSE_INCLUDED.
     */
    readonly licenseModel: string;
    /**
     * Additional information about the current lifecycle state.
     */
    readonly lifecycleDetails: string;
    /**
     * The memory allocated in GBs.
     */
    readonly memorySizeInGbs: number;
    readonly ocpuCount: number;
    readonly ocpusEnabled: number;
    /**
     * The shape of the Exadata infrastructure. The shape determines the amount of CPU, storage, and memory resources allocated to the instance.
     */
    readonly shape: string;
    /**
     * The public key portion of one or more key pairs used for SSH access to the VM cluster.
     */
    readonly sshPublicKeys: string[];
    /**
     * The current state of the VM cluster.
     */
    readonly state: string;
    /**
     * Operating system version of the image.
     */
    readonly systemVersion: string;
    /**
     * The date and time that the VM cluster was created.
     */
    readonly timeCreated: string;
    /**
     * The time zone of the Exadata infrastructure. For details, see [Exadata Infrastructure Time Zones](https://docs.cloud.oracle.com/iaas/Content/Database/References/timezones.htm).
     */
    readonly timeZone: string;
    readonly vmClusterId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VM cluster network.
     */
    readonly vmClusterNetworkId: string;
}

export function getVmClusterOutput(args: GetVmClusterOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetVmClusterResult> {
    return pulumi.output(args).apply(a => getVmCluster(a, opts))
}

/**
 * A collection of arguments for invoking getVmCluster.
 */
export interface GetVmClusterOutputArgs {
    /**
     * The VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    vmClusterId: pulumi.Input<string>;
}