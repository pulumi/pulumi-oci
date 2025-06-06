// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Connect Harness resource in Oracle Cloud Infrastructure Streaming service.
 *
 * Gets detailed information about a connect harness.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testConnectHarness = oci.Streaming.getConnectHarness({
 *     connectHarnessId: testConnectHarnes.id,
 * });
 * ```
 */
export function getConnectHarness(args: GetConnectHarnessArgs, opts?: pulumi.InvokeOptions): Promise<GetConnectHarnessResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Streaming/getConnectHarness:getConnectHarness", {
        "connectHarnessId": args.connectHarnessId,
    }, opts);
}

/**
 * A collection of arguments for invoking getConnectHarness.
 */
export interface GetConnectHarnessArgs {
    /**
     * The OCID of the connect harness.
     */
    connectHarnessId: string;
}

/**
 * A collection of values returned by getConnectHarness.
 */
export interface GetConnectHarnessResult {
    /**
     * The OCID of the compartment that contains the connect harness.
     */
    readonly compartmentId: string;
    readonly connectHarnessId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations": {"CostCenter": "42"}}'
     */
    readonly definedTags: {[key: string]: string};
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair that is applied with no predefined name, type, or namespace. Exists for cross-compatibility only. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The OCID of the connect harness.
     */
    readonly id: string;
    /**
     * Any additional details about the current state of the connect harness.
     */
    readonly lifecycleStateDetails: string;
    /**
     * The name of the connect harness. Avoid entering confidential information.  Example: `JDBCConnector`
     */
    readonly name: string;
    /**
     * The current state of the connect harness.
     */
    readonly state: string;
    /**
     * The date and time the connect harness was created, expressed in in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2018-04-20T00:00:07.405Z`
     */
    readonly timeCreated: string;
}
/**
 * This data source provides details about a specific Connect Harness resource in Oracle Cloud Infrastructure Streaming service.
 *
 * Gets detailed information about a connect harness.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testConnectHarness = oci.Streaming.getConnectHarness({
 *     connectHarnessId: testConnectHarnes.id,
 * });
 * ```
 */
export function getConnectHarnessOutput(args: GetConnectHarnessOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetConnectHarnessResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Streaming/getConnectHarness:getConnectHarness", {
        "connectHarnessId": args.connectHarnessId,
    }, opts);
}

/**
 * A collection of arguments for invoking getConnectHarness.
 */
export interface GetConnectHarnessOutputArgs {
    /**
     * The OCID of the connect harness.
     */
    connectHarnessId: pulumi.Input<string>;
}
