// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Importable Compute Entity resource in Oracle Cloud Infrastructure Opsi service.
 *
 * Gets a list of available compute intances running cloud agent to add a new hostInsight.  An Compute entity is "available"
 * and will be shown if all the following conditions are true:
 *    1. Compute is running OCA
 *    2. Oracle Cloud Infrastructure Management Agent is not enabled or If Oracle Cloud Infrastructure Management Agent is enabled
 *       2.1 The agent OCID is not already being used for an existing hostInsight.
 *       2.2 The agent availabilityStatus = 'ACTIVE'
 *       2.3 The agent lifecycleState = 'ACTIVE'
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testImportableComputeEntity = oci.Opsi.getImportableComputeEntity({
 *     compartmentId: _var.compartment_id,
 * });
 * ```
 */
export function getImportableComputeEntity(args: GetImportableComputeEntityArgs, opts?: pulumi.InvokeOptions): Promise<GetImportableComputeEntityResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Opsi/getImportableComputeEntity:getImportableComputeEntity", {
        "compartmentId": args.compartmentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getImportableComputeEntity.
 */
export interface GetImportableComputeEntityArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
}

/**
 * A collection of values returned by getImportableComputeEntity.
 */
export interface GetImportableComputeEntityResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Array of importable compute entity objects.
     */
    readonly items: outputs.Opsi.GetImportableComputeEntityItem[];
}

export function getImportableComputeEntityOutput(args: GetImportableComputeEntityOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetImportableComputeEntityResult> {
    return pulumi.output(args).apply(a => getImportableComputeEntity(a, opts))
}

/**
 * A collection of arguments for invoking getImportableComputeEntity.
 */
export interface GetImportableComputeEntityOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
}