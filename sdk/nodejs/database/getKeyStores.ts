// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Key Stores in Oracle Cloud Infrastructure Database service.
 *
 * Gets a list of key stores in the specified compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testKeyStores = oci.Database.getKeyStores({
 *     compartmentId: _var.compartment_id,
 * });
 * ```
 */
export function getKeyStores(args: GetKeyStoresArgs, opts?: pulumi.InvokeOptions): Promise<GetKeyStoresResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Database/getKeyStores:getKeyStores", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getKeyStores.
 */
export interface GetKeyStoresArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: string;
    filters?: inputs.Database.GetKeyStoresFilter[];
}

/**
 * A collection of values returned by getKeyStores.
 */
export interface GetKeyStoresResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.Database.GetKeyStoresFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of key_stores.
     */
    readonly keyStores: outputs.Database.GetKeyStoresKeyStore[];
}

export function getKeyStoresOutput(args: GetKeyStoresOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetKeyStoresResult> {
    return pulumi.output(args).apply(a => getKeyStores(a, opts))
}

/**
 * A collection of arguments for invoking getKeyStores.
 */
export interface GetKeyStoresOutputArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Database.GetKeyStoresFilterArgs>[]>;
}