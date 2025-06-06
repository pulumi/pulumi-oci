// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific View resource in Oracle Cloud Infrastructure DNS service.
 *
 * Gets information about a specific view.
 *
 * Note that attempting to get a
 * view in the DELETED lifecycleState will result in a `404` response to be
 * consistent with other operations of the API.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testView = oci.Dns.getView({
 *     viewId: testViewOciDnsView.id,
 *     scope: "PRIVATE",
 * });
 * ```
 */
export function getView(args?: GetViewArgs, opts?: pulumi.InvokeOptions): Promise<GetViewResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Dns/getView:getView", {
        "scope": args.scope,
        "viewId": args.viewId,
    }, opts);
}

/**
 * A collection of arguments for invoking getView.
 */
export interface GetViewArgs {
    /**
     * Value must be `PRIVATE` when listing views for private zones.
     */
    scope?: string;
    /**
     * The OCID of the target view.
     */
    viewId?: string;
}

/**
 * A collection of values returned by getView.
 */
export interface GetViewResult {
    /**
     * The OCID of the owning compartment.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    readonly definedTags: {[key: string]: string};
    /**
     * The display name of the view.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The OCID of the view.
     */
    readonly id: string;
    /**
     * A Boolean flag indicating whether or not parts of the resource are unable to be explicitly managed.
     */
    readonly isProtected: boolean;
    readonly scope?: string;
    /**
     * The canonical absolute URL of the resource.
     */
    readonly self: string;
    /**
     * The current state of the resource.
     */
    readonly state: string;
    /**
     * The date and time the resource was created in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
     */
    readonly timeCreated: string;
    /**
     * The date and time the resource was last updated in "YYYY-MM-ddThh:mm:ssZ" format with a Z offset, as defined by RFC 3339.
     */
    readonly timeUpdated: string;
    readonly viewId?: string;
}
/**
 * This data source provides details about a specific View resource in Oracle Cloud Infrastructure DNS service.
 *
 * Gets information about a specific view.
 *
 * Note that attempting to get a
 * view in the DELETED lifecycleState will result in a `404` response to be
 * consistent with other operations of the API.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testView = oci.Dns.getView({
 *     viewId: testViewOciDnsView.id,
 *     scope: "PRIVATE",
 * });
 * ```
 */
export function getViewOutput(args?: GetViewOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetViewResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Dns/getView:getView", {
        "scope": args.scope,
        "viewId": args.viewId,
    }, opts);
}

/**
 * A collection of arguments for invoking getView.
 */
export interface GetViewOutputArgs {
    /**
     * Value must be `PRIVATE` when listing views for private zones.
     */
    scope?: pulumi.Input<string>;
    /**
     * The OCID of the target view.
     */
    viewId?: pulumi.Input<string>;
}
