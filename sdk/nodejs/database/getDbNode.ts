// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Db Node resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets information about the specified database node.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDbNode = oci.Database.getDbNode({
 *     dbNodeId: _var.db_node_id,
 * });
 * ```
 */
export function getDbNode(args: GetDbNodeArgs, opts?: pulumi.InvokeOptions): Promise<GetDbNodeResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Database/getDbNode:getDbNode", {
        "dbNodeId": args.dbNodeId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDbNode.
 */
export interface GetDbNodeArgs {
    /**
     * The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbNodeId: string;
}

/**
 * A collection of values returned by getDbNode.
 */
export interface GetDbNodeResult {
    /**
     * Additional information about the planned maintenance.
     */
    readonly additionalDetails: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup IP address associated with the database node.
     */
    readonly backupIpId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the second backup VNIC.
     */
    readonly backupVnic2id: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup VNIC.
     */
    readonly backupVnicId: string;
    /**
     * The number of CPU cores enabled on the Db node.
     */
    readonly cpuCoreCount: number;
    readonly dbNodeId: string;
    /**
     * The allocated local node storage in GBs on the Db node.
     */
    readonly dbNodeStorageSizeInGbs: number;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exacc Db server associated with the database node.
     */
    readonly dbServerId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system.
     */
    readonly dbSystemId: string;
    /**
     * The name of the Fault Domain the instance is contained in.
     */
    readonly faultDomain: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the host IP address associated with the database node.
     */
    readonly hostIpId: string;
    /**
     * The host name for the database node.
     */
    readonly hostname: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The type of database node maintenance.
     */
    readonly maintenanceType: string;
    /**
     * The allocated memory in GBs on the Db node.
     */
    readonly memorySizeInGbs: number;
    /**
     * The size (in GB) of the block storage volume allocation for the DB system. This attribute applies only for virtual machine DB systems.
     */
    readonly softwareStorageSizeInGb: number;
    /**
     * The current state of the database node.
     */
    readonly state: string;
    /**
     * The date and time that the database node was created.
     */
    readonly timeCreated: string;
    /**
     * End date and time of maintenance window.
     */
    readonly timeMaintenanceWindowEnd: string;
    /**
     * Start date and time of maintenance window.
     */
    readonly timeMaintenanceWindowStart: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the second VNIC.
     */
    readonly vnic2id: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VNIC.
     */
    readonly vnicId: string;
}

export function getDbNodeOutput(args: GetDbNodeOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetDbNodeResult> {
    return pulumi.output(args).apply(a => getDbNode(a, opts))
}

/**
 * A collection of arguments for invoking getDbNode.
 */
export interface GetDbNodeOutputArgs {
    /**
     * The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    dbNodeId: pulumi.Input<string>;
}
