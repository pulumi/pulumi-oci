// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific External Db Home resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the details for the external DB home specified by `externalDbHomeId`.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalDbHome = oci.DatabaseManagement.getExternalDbHome({
 *     externalDbHomeId: oci_database_management_external_db_home.test_external_db_home.id,
 * });
 * ```
 */
export function getExternalDbHome(args: GetExternalDbHomeArgs, opts?: pulumi.InvokeOptions): Promise<GetExternalDbHomeResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseManagement/getExternalDbHome:getExternalDbHome", {
        "externalDbHomeId": args.externalDbHomeId,
    }, opts);
}

/**
 * A collection of arguments for invoking getExternalDbHome.
 */
export interface GetExternalDbHomeArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database home.
     */
    externalDbHomeId: string;
}

/**
 * A collection of values returned by getExternalDbHome.
 */
export interface GetExternalDbHomeResult {
    /**
     * The additional details of the DB home defined in `{"key": "value"}` format. Example: `{"bar-key": "value"}`
     */
    readonly additionalDetails: {[key: string]: any};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The name of the external DB home.
     */
    readonly componentName: string;
    /**
     * The user-friendly name for the external DB home. The name does not have to be unique.
     */
    readonly displayName: string;
    readonly externalDbHomeId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external DB system that the DB home is a part of.
     */
    readonly externalDbSystemId: string;
    /**
     * The location of the DB home.
     */
    readonly homeDirectory: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Additional information about the current lifecycle state.
     */
    readonly lifecycleDetails: string;
    /**
     * The current lifecycle state of the external DB home.
     */
    readonly state: string;
    /**
     * The date and time the external DB home was created.
     */
    readonly timeCreated: string;
    /**
     * The date and time the external DB home was last updated.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific External Db Home resource in Oracle Cloud Infrastructure Database Management service.
 *
 * Gets the details for the external DB home specified by `externalDbHomeId`.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalDbHome = oci.DatabaseManagement.getExternalDbHome({
 *     externalDbHomeId: oci_database_management_external_db_home.test_external_db_home.id,
 * });
 * ```
 */
export function getExternalDbHomeOutput(args: GetExternalDbHomeOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetExternalDbHomeResult> {
    return pulumi.output(args).apply((a: any) => getExternalDbHome(a, opts))
}

/**
 * A collection of arguments for invoking getExternalDbHome.
 */
export interface GetExternalDbHomeOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the external database home.
     */
    externalDbHomeId: pulumi.Input<string>;
}