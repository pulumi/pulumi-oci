// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of External Exadata Infrastructures in Oracle Cloud Infrastructure Database Management service.
 *
 * Lists the Exadata infrastructure resources in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalExadataInfrastructures = oci.DatabaseManagement.getExternalExadataInfrastructures({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.external_exadata_infrastructure_display_name,
 * });
 * ```
 */
export function getExternalExadataInfrastructures(args: GetExternalExadataInfrastructuresArgs, opts?: pulumi.InvokeOptions): Promise<GetExternalExadataInfrastructuresResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DatabaseManagement/getExternalExadataInfrastructures:getExternalExadataInfrastructures", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getExternalExadataInfrastructures.
 */
export interface GetExternalExadataInfrastructuresArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * The optional single value query filter parameter on the entity display name.
     */
    displayName?: string;
    filters?: inputs.DatabaseManagement.GetExternalExadataInfrastructuresFilter[];
}

/**
 * A collection of values returned by getExternalExadataInfrastructures.
 */
export interface GetExternalExadataInfrastructuresResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * The name of the Exadata resource. English letters, numbers, "-", "_" and "." only.
     */
    readonly displayName?: string;
    /**
     * The list of external_exadata_infrastructure_collection.
     */
    readonly externalExadataInfrastructureCollections: outputs.DatabaseManagement.GetExternalExadataInfrastructuresExternalExadataInfrastructureCollection[];
    readonly filters?: outputs.DatabaseManagement.GetExternalExadataInfrastructuresFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
/**
 * This data source provides the list of External Exadata Infrastructures in Oracle Cloud Infrastructure Database Management service.
 *
 * Lists the Exadata infrastructure resources in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testExternalExadataInfrastructures = oci.DatabaseManagement.getExternalExadataInfrastructures({
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.external_exadata_infrastructure_display_name,
 * });
 * ```
 */
export function getExternalExadataInfrastructuresOutput(args: GetExternalExadataInfrastructuresOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetExternalExadataInfrastructuresResult> {
    return pulumi.output(args).apply((a: any) => getExternalExadataInfrastructures(a, opts))
}

/**
 * A collection of arguments for invoking getExternalExadataInfrastructures.
 */
export interface GetExternalExadataInfrastructuresOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The optional single value query filter parameter on the entity display name.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DatabaseManagement.GetExternalExadataInfrastructuresFilterArgs>[]>;
}