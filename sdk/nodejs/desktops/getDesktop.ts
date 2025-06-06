// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Desktop resource in Oracle Cloud Infrastructure Desktops service.
 *
 * Provides information about the desktop with the specified OCID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDesktop = oci.Desktops.getDesktop({
 *     desktopId: testDesktopOciDesktopsDesktop.id,
 * });
 * ```
 */
export function getDesktop(args: GetDesktopArgs, opts?: pulumi.InvokeOptions): Promise<GetDesktopResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Desktops/getDesktop:getDesktop", {
        "desktopId": args.desktopId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDesktop.
 */
export interface GetDesktopArgs {
    /**
     * The OCID of the desktop.
     */
    desktopId: string;
}

/**
 * A collection of values returned by getDesktop.
 */
export interface GetDesktopResult {
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    readonly desktopId: string;
    /**
     * Provides the settings for desktop and client device options, such as audio in and out, client drive mapping, and clipboard access.
     */
    readonly devicePolicies: outputs.Desktops.GetDesktopDevicePolicy[];
    /**
     * A user friendly display name. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * Provides information about where a desktop is hosted.
     */
    readonly hostingOptions: outputs.Desktops.GetDesktopHostingOption[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The OCID of the desktop pool the desktop is a member of.
     */
    readonly poolId: string;
    /**
     * The state of the desktop.
     */
    readonly state: string;
    /**
     * The date and time the resource was created.
     */
    readonly timeCreated: string;
    /**
     * The owner of the desktop.
     */
    readonly userName: string;
}
/**
 * This data source provides details about a specific Desktop resource in Oracle Cloud Infrastructure Desktops service.
 *
 * Provides information about the desktop with the specified OCID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDesktop = oci.Desktops.getDesktop({
 *     desktopId: testDesktopOciDesktopsDesktop.id,
 * });
 * ```
 */
export function getDesktopOutput(args: GetDesktopOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDesktopResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Desktops/getDesktop:getDesktop", {
        "desktopId": args.desktopId,
    }, opts);
}

/**
 * A collection of arguments for invoking getDesktop.
 */
export interface GetDesktopOutputArgs {
    /**
     * The OCID of the desktop.
     */
    desktopId: pulumi.Input<string>;
}
