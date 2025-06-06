// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Bds Instance Api Key resource in Oracle Cloud Infrastructure Big Data Service service.
 *
 * Returns the user's API key information for the given ID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBdsInstanceApiKey = oci.BigDataService.getBdsInstanceApiKey({
 *     apiKeyId: testApiKey.id,
 *     bdsInstanceId: testBdsInstance.id,
 * });
 * ```
 */
export function getBdsInstanceApiKeys(args: GetBdsInstanceApiKeysArgs, opts?: pulumi.InvokeOptions): Promise<GetBdsInstanceApiKeysResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:BigDataService/getBdsInstanceApiKeys:getBdsInstanceApiKeys", {
        "bdsInstanceId": args.bdsInstanceId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
        "userId": args.userId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBdsInstanceApiKeys.
 */
export interface GetBdsInstanceApiKeysArgs {
    /**
     * The OCID of the cluster.
     */
    bdsInstanceId: string;
    displayName?: string;
    filters?: inputs.BigDataService.GetBdsInstanceApiKeysFilter[];
    /**
     * The current status of the API key.
     */
    state?: string;
    /**
     * The user OCID for which this API key was created.
     */
    userId?: string;
}

/**
 * A collection of values returned by getBdsInstanceApiKeys.
 */
export interface GetBdsInstanceApiKeysResult {
    /**
     * The list of bds_api_keys.
     */
    readonly bdsApiKeys: outputs.BigDataService.GetBdsInstanceApiKeysBdsApiKey[];
    readonly bdsInstanceId: string;
    readonly displayName?: string;
    readonly filters?: outputs.BigDataService.GetBdsInstanceApiKeysFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current status of the API key.
     */
    readonly state?: string;
    /**
     * The user OCID for which this API key was created.
     */
    readonly userId?: string;
}
/**
 * This data source provides details about a specific Bds Instance Api Key resource in Oracle Cloud Infrastructure Big Data Service service.
 *
 * Returns the user's API key information for the given ID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBdsInstanceApiKey = oci.BigDataService.getBdsInstanceApiKey({
 *     apiKeyId: testApiKey.id,
 *     bdsInstanceId: testBdsInstance.id,
 * });
 * ```
 */
export function getBdsInstanceApiKeysOutput(args: GetBdsInstanceApiKeysOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetBdsInstanceApiKeysResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:BigDataService/getBdsInstanceApiKeys:getBdsInstanceApiKeys", {
        "bdsInstanceId": args.bdsInstanceId,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
        "userId": args.userId,
    }, opts);
}

/**
 * A collection of arguments for invoking getBdsInstanceApiKeys.
 */
export interface GetBdsInstanceApiKeysOutputArgs {
    /**
     * The OCID of the cluster.
     */
    bdsInstanceId: pulumi.Input<string>;
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.BigDataService.GetBdsInstanceApiKeysFilterArgs>[]>;
    /**
     * The current status of the API key.
     */
    state?: pulumi.Input<string>;
    /**
     * The user OCID for which this API key was created.
     */
    userId?: pulumi.Input<string>;
}
