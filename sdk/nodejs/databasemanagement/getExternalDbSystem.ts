// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific External Db System resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the details for the external DB system specified by `externalDbSystemId`.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalDbSystem = oci.DatabaseManagement.getExternalDbSystem({
 *     externalDbSystemId: oci_database_management_external_db_system.test_external_db_system.id,
 * });
 * ```
 */
export function getExternalDbSystem(args: GetExternalDbSystemArgs, opts?: pulumi.InvokeOptions): Promise<GetExternalDbSystemResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseManagement/getExternalDbSystem:getExternalDbSystem", {
        "externalDbSystemId": args.externalDbSystemId,
    }, opts);
}

/**
 * A collection of arguments for invoking getExternalDbSystem.
 */
export interface GetExternalDbSystemArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
     */
    externalDbSystemId: string;
}

/**
 * A collection of values returned by getExternalDbSystem.
 */
export interface GetExternalDbSystemResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The details required to enable Database Management for an external DB system.
     */
    readonly databaseManagementConfigs: outputs.DatabaseManagement.GetExternalDbSystemDatabaseManagementConfig[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DB system discovery.
     */
    readonly dbSystemDiscoveryId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management agent used during the discovery of the DB system.
     */
    readonly discoveryAgentId: string;
    /**
     * The user-friendly name for the DB system. The name does not have to be unique.
     */
    readonly displayName: string;
    readonly externalDbSystemId: string;
    /**
     * The Oracle Grid home directory in case of cluster-based DB system and Oracle home directory in case of single instance-based DB system.
     */
    readonly homeDirectory: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
     */
    readonly id: string;
    /**
     * Indicates whether the DB system is a cluster DB system or not.
     */
    readonly isCluster: boolean;
    /**
     * Additional information about the current lifecycle state.
     */
    readonly lifecycleDetails: string;
    /**
     * The current lifecycle state of the external DB system resource.
     */
    readonly state: string;
    /**
     * The date and time the external DB system was created.
     */
    readonly timeCreated: string;
    /**
     * The date and time the external DB system was last updated.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific External Db System resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the details for the external DB system specified by `externalDbSystemId`.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalDbSystem = oci.DatabaseManagement.getExternalDbSystem({
 *     externalDbSystemId: oci_database_management_external_db_system.test_external_db_system.id,
 * });
 * ```
 */
export function getExternalDbSystemOutput(args: GetExternalDbSystemOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetExternalDbSystemResult> {
    return pulumi.output(args).apply((a: any) => getExternalDbSystem(a, opts))
}

/**
 * A collection of arguments for invoking getExternalDbSystem.
 */
export interface GetExternalDbSystemOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system.
     */
    externalDbSystemId: pulumi.Input<string>;
}