// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Key Store resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets information about the specified key store.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testKeyStore = oci.Database.getKeyStore({
 *     keyStoreId: testKeyStoreOciDatabaseKeyStore.id,
 * });
 * ```
 */
export function getKeyStore(args: GetKeyStoreArgs, opts?: pulumi.InvokeOptions): Promise<GetKeyStoreResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Database/getKeyStore:getKeyStore", {
        "keyStoreId": args.keyStoreId,
    }, opts);
}

/**
 * A collection of arguments for invoking getKeyStore.
 */
export interface GetKeyStoreArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
     */
    keyStoreId: string;
}

/**
 * A collection of values returned by getKeyStore.
 */
export interface GetKeyStoreResult {
    /**
     * List of databases associated with the key store.
     */
    readonly associatedDatabases: outputs.Database.GetKeyStoreAssociatedDatabase[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    readonly confirmDetailsTrigger: number;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    readonly definedTags: {[key: string]: string};
    /**
     * The user-friendly name for the key store. The name does not need to be unique.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
     */
    readonly id: string;
    readonly keyStoreId: string;
    /**
     * Additional information about the current lifecycle state.
     */
    readonly lifecycleDetails: string;
    /**
     * The current state of the key store.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The date and time that the key store was created.
     */
    readonly timeCreated: string;
    /**
     * Key store type details.
     */
    readonly typeDetails: outputs.Database.GetKeyStoreTypeDetail[];
}
/**
 * This data source provides details about a specific Key Store resource in Oracle Cloud Infrastructure Database service.
 *
 * Gets information about the specified key store.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testKeyStore = oci.Database.getKeyStore({
 *     keyStoreId: testKeyStoreOciDatabaseKeyStore.id,
 * });
 * ```
 */
export function getKeyStoreOutput(args: GetKeyStoreOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetKeyStoreResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Database/getKeyStore:getKeyStore", {
        "keyStoreId": args.keyStoreId,
    }, opts);
}

/**
 * A collection of arguments for invoking getKeyStore.
 */
export interface GetKeyStoreOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the key store.
     */
    keyStoreId: pulumi.Input<string>;
}
