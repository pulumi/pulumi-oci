// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Instance Configuration resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets the specified instance configuration
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInstanceConfiguration = oci.Core.getInstanceConfiguration({
 *     instanceConfigurationId: testInstanceConfigurationOciCoreInstanceConfiguration.id,
 * });
 * ```
 */
export function getInstanceConfiguration(args: GetInstanceConfigurationArgs, opts?: pulumi.InvokeOptions): Promise<GetInstanceConfigurationResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Core/getInstanceConfiguration:getInstanceConfiguration", {
        "instanceConfigurationId": args.instanceConfigurationId,
    }, opts);
}

/**
 * A collection of arguments for invoking getInstanceConfiguration.
 */
export interface GetInstanceConfigurationArgs {
    /**
     * The OCID of the instance configuration.
     */
    instanceConfigurationId: string;
}

/**
 * A collection of values returned by getInstanceConfiguration.
 */
export interface GetInstanceConfigurationResult {
    /**
     * The OCID of the compartment containing images to search
     */
    readonly compartmentId: string;
    /**
     * Parameters that were not specified when the instance configuration was created, but that are required to launch an instance from the instance configuration. See the [LaunchInstanceConfiguration](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Instance/LaunchInstanceConfiguration) operation.
     */
    readonly deferredFields: string[];
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The OCID of the volume backup.
     */
    readonly id: string;
    readonly instanceConfigurationId: string;
    readonly instanceDetails: outputs.Core.GetInstanceConfigurationInstanceDetail[];
    readonly instanceId: string;
    readonly source: string;
    /**
     * The date and time the instance configuration was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    readonly timeCreated: string;
}
/**
 * This data source provides details about a specific Instance Configuration resource in Oracle Cloud Infrastructure Core service.
 *
 * Gets the specified instance configuration
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInstanceConfiguration = oci.Core.getInstanceConfiguration({
 *     instanceConfigurationId: testInstanceConfigurationOciCoreInstanceConfiguration.id,
 * });
 * ```
 */
export function getInstanceConfigurationOutput(args: GetInstanceConfigurationOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetInstanceConfigurationResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Core/getInstanceConfiguration:getInstanceConfiguration", {
        "instanceConfigurationId": args.instanceConfigurationId,
    }, opts);
}

/**
 * A collection of arguments for invoking getInstanceConfiguration.
 */
export interface GetInstanceConfigurationOutputArgs {
    /**
     * The OCID of the instance configuration.
     */
    instanceConfigurationId: pulumi.Input<string>;
}
