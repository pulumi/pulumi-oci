// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Managed List resource in Oracle Cloud Infrastructure Cloud Guard service.
 *
 * Returns a managed list identified by managedListId.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedList = oci.CloudGuard.getManagedList({
 *     managedListId: testManagedListOciCloudGuardManagedList.id,
 * });
 * ```
 */
export function getManagedList(args: GetManagedListArgs, opts?: pulumi.InvokeOptions): Promise<GetManagedListResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:CloudGuard/getManagedList:getManagedList", {
        "managedListId": args.managedListId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedList.
 */
export interface GetManagedListArgs {
    /**
     * The managed list OCID to be passed in the request.
     */
    managedListId: string;
}

/**
 * A collection of values returned by getManagedList.
 */
export interface GetManagedListResult {
    /**
     * Compartment OCID where the resource is created
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * Managed list description
     */
    readonly description: string;
    /**
     * Managed list display name
     */
    readonly displayName: string;
    /**
     * Provider of the managed list feed
     */
    readonly feedProvider: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * Unique identifier that can't be changed after creation
     */
    readonly id: string;
    /**
     * Is this list editable?
     */
    readonly isEditable: boolean;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state. [DEPRECATE]
     */
    readonly lifecyleDetails: string;
    /**
     * List of items in the managed list
     */
    readonly listItems: string[];
    /**
     * Type of information contained in the managed list
     */
    readonly listType: string;
    readonly managedListId: string;
    /**
     * OCID of the source managed list
     */
    readonly sourceManagedListId: string;
    /**
     * The current lifecycle state of the resource
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The date and time the managed list was created. Format defined by RFC3339.
     */
    readonly timeCreated: string;
    /**
     * The date and time the managed list was last updated. Format defined by RFC3339.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Managed List resource in Oracle Cloud Infrastructure Cloud Guard service.
 *
 * Returns a managed list identified by managedListId.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testManagedList = oci.CloudGuard.getManagedList({
 *     managedListId: testManagedListOciCloudGuardManagedList.id,
 * });
 * ```
 */
export function getManagedListOutput(args: GetManagedListOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetManagedListResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:CloudGuard/getManagedList:getManagedList", {
        "managedListId": args.managedListId,
    }, opts);
}

/**
 * A collection of arguments for invoking getManagedList.
 */
export interface GetManagedListOutputArgs {
    /**
     * The managed list OCID to be passed in the request.
     */
    managedListId: pulumi.Input<string>;
}
