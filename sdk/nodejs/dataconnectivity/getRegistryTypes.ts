// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Registry Types in Oracle Cloud Infrastructure Data Connectivity service.
 *
 * This endpoint retrieves a list of all the supported connector types.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testRegistryTypes = oci.DataConnectivity.getRegistryTypes({
 *     registryId: oci_data_connectivity_registry.test_registry.id,
 *     name: _var.registry_type_name,
 *     type: _var.registry_type_type,
 * });
 * ```
 */
export function getRegistryTypes(args: GetRegistryTypesArgs, opts?: pulumi.InvokeOptions): Promise<GetRegistryTypesResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:DataConnectivity/getRegistryTypes:getRegistryTypes", {
        "filters": args.filters,
        "name": args.name,
        "registryId": args.registryId,
        "type": args.type,
    }, opts);
}

/**
 * A collection of arguments for invoking getRegistryTypes.
 */
export interface GetRegistryTypesArgs {
    filters?: inputs.DataConnectivity.GetRegistryTypesFilter[];
    /**
     * Used to filter by the name of the object.
     */
    name?: string;
    /**
     * The registry OCID.
     */
    registryId: string;
    /**
     * Type of the object to filter the results with.
     */
    type?: string;
}

/**
 * A collection of values returned by getRegistryTypes.
 */
export interface GetRegistryTypesResult {
    readonly filters?: outputs.DataConnectivity.GetRegistryTypesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The name of of the attribute.
     */
    readonly name?: string;
    readonly registryId: string;
    readonly type?: string;
    /**
     * The list of types_summary_collection.
     */
    readonly typesSummaryCollections: outputs.DataConnectivity.GetRegistryTypesTypesSummaryCollection[];
}

export function getRegistryTypesOutput(args: GetRegistryTypesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetRegistryTypesResult> {
    return pulumi.output(args).apply(a => getRegistryTypes(a, opts))
}

/**
 * A collection of arguments for invoking getRegistryTypes.
 */
export interface GetRegistryTypesOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.DataConnectivity.GetRegistryTypesFilterArgs>[]>;
    /**
     * Used to filter by the name of the object.
     */
    name?: pulumi.Input<string>;
    /**
     * The registry OCID.
     */
    registryId: pulumi.Input<string>;
    /**
     * Type of the object to filter the results with.
     */
    type?: pulumi.Input<string>;
}