// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of External Db Systems in Oracle Cloud Infrastructure Database Management service.
 *
 * Lists the external DB systems in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalDbSystems = oci.DatabaseManagement.getExternalDbSystems({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.external_db_system_display_name,
 * });
 * ```
 */
export function getExternalDbSystems(args: GetExternalDbSystemsArgs, opts?: pulumi.InvokeOptions): Promise<GetExternalDbSystemsResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseManagement/getExternalDbSystems:getExternalDbSystems", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getExternalDbSystems.
 */
export interface GetExternalDbSystemsArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * A filter to only return the resources that match the entire display name.
     */
    displayName?: string;
    filters?: inputs.DatabaseManagement.GetExternalDbSystemsFilter[];
}

/**
 * A collection of values returned by getExternalDbSystems.
 */
export interface GetExternalDbSystemsResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The user-friendly name for the DB system. The name does not have to be unique.
     */
    readonly displayName?: string;
    /**
     * The list of external_db_system_collection.
     */
    readonly externalDbSystemCollections: outputs.DatabaseManagement.GetExternalDbSystemsExternalDbSystemCollection[];
    readonly filters?: outputs.DatabaseManagement.GetExternalDbSystemsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
/**
 * This data source provides the list of External Db Systems in Oracle Cloud Infrastructure Database Management service.
 *
 * Lists the external DB systems in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalDbSystems = oci.DatabaseManagement.getExternalDbSystems({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.external_db_system_display_name,
 * });
 * ```
 */
export function getExternalDbSystemsOutput(args: GetExternalDbSystemsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetExternalDbSystemsResult> {
    return pulumi.output(args).apply((a: any) => getExternalDbSystems(a, opts))
}

/**
 * A collection of arguments for invoking getExternalDbSystems.
 */
export interface GetExternalDbSystemsOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to only return the resources that match the entire display name.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.GetExternalDbSystemsFilterArgs>[]>;
}