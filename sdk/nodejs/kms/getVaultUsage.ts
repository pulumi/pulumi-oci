// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Vault Usage resource in Oracle Cloud Infrastructure Kms service.
 *
 * Gets the count of keys and key versions in the specified vault to calculate usage against service limits.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVaultUsage = oci.Kms.getVaultUsage({
 *     vaultId: oci_kms_vault.test_vault.id,
 * });
 * ```
 */
export function getVaultUsage(args: GetVaultUsageArgs, opts?: pulumi.InvokeOptions): Promise<GetVaultUsageResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Kms/getVaultUsage:getVaultUsage", {
        "vaultId": args.vaultId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVaultUsage.
 */
export interface GetVaultUsageArgs {
    /**
     * The OCID of the vault.
     */
    vaultId: string;
}

/**
 * A collection of values returned by getVaultUsage.
 */
export interface GetVaultUsageResult {
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The number of keys in this vault, across all compartments, excluding keys in a `DELETED` state.
     */
    readonly keyCount: number;
    /**
     * The number of key versions in this vault, across all compartments, excluding key versions in a `DELETED` state.
     */
    readonly keyVersionCount: number;
    /**
     * The number of keys in this vault that persist on the server, across all compartments, excluding keys in a `DELETED` state.
     */
    readonly softwareKeyCount: number;
    /**
     * The number of key versions in this vault that persist on the server, across all compartments, excluding key versions in a `DELETED` state.
     */
    readonly softwareKeyVersionCount: number;
    readonly vaultId: string;
}

export function getVaultUsageOutput(args: GetVaultUsageOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetVaultUsageResult> {
    return pulumi.output(args).apply(a => getVaultUsage(a, opts))
}

/**
 * A collection of arguments for invoking getVaultUsage.
 */
export interface GetVaultUsageOutputArgs {
    /**
     * The OCID of the vault.
     */
    vaultId: pulumi.Input<string>;
}