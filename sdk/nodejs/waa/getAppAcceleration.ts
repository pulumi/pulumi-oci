// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Web App Acceleration resource in Oracle Cloud Infrastructure Waa service.
 *
 * Gets a WebAppAcceleration by OCID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testWebAppAcceleration = oci.Waa.getAppAcceleration({
 *     webAppAccelerationId: testWebAppAccelerationOciWaaWebAppAcceleration.id,
 * });
 * ```
 */
export function getAppAcceleration(args: GetAppAccelerationArgs, opts?: pulumi.InvokeOptions): Promise<GetAppAccelerationResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Waa/getAppAcceleration:getAppAcceleration", {
        "webAppAccelerationId": args.webAppAccelerationId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAppAcceleration.
 */
export interface GetAppAccelerationArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppAcceleration.
     */
    webAppAccelerationId: string;
}

/**
 * A collection of values returned by getAppAcceleration.
 */
export interface GetAppAccelerationResult {
    /**
     * Type of the WebAppFirewall, as example LOAD_BALANCER.
     */
    readonly backendType: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * WebAppAcceleration display name, can be renamed.
     */
    readonly displayName: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppAcceleration.
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in FAILED state.
     */
    readonly lifecycleDetails: string;
    /**
     * LoadBalancer [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) to which the WebAppAccelerationPolicy is attached to.
     */
    readonly loadBalancerId: string;
    /**
     * The current state of the WebAppAcceleration.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The time the WebAppAcceleration was created. An RFC3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * The time the WebAppAcceleration was updated. An RFC3339 formatted datetime string.
     */
    readonly timeUpdated: string;
    readonly webAppAccelerationId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of WebAppAccelerationPolicy, which is attached to the resource.
     */
    readonly webAppAccelerationPolicyId: string;
}
/**
 * This data source provides details about a specific Web App Acceleration resource in Oracle Cloud Infrastructure Waa service.
 *
 * Gets a WebAppAcceleration by OCID.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testWebAppAcceleration = oci.Waa.getAppAcceleration({
 *     webAppAccelerationId: testWebAppAccelerationOciWaaWebAppAcceleration.id,
 * });
 * ```
 */
export function getAppAccelerationOutput(args: GetAppAccelerationOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAppAccelerationResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Waa/getAppAcceleration:getAppAcceleration", {
        "webAppAccelerationId": args.webAppAccelerationId,
    }, opts);
}

/**
 * A collection of arguments for invoking getAppAcceleration.
 */
export interface GetAppAccelerationOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebAppAcceleration.
     */
    webAppAccelerationId: pulumi.Input<string>;
}
