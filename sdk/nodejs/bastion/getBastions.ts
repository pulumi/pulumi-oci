// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Bastions in Oracle Cloud Infrastructure Bastion service.
 *
 * Retrieves a list of BastionSummary objects in a compartment. Bastions provide secured, public access to target resources in the cloud that you cannot otherwise reach from the internet.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBastions = oci.Bastion.getBastions({
 *     compartmentId: compartmentId,
 *     bastionId: testBastion.id,
 *     bastionLifecycleState: bastionBastionLifecycleState,
 *     name: bastionName,
 * });
 * ```
 */
export function getBastions(args: GetBastionsArgs, opts?: pulumi.InvokeOptions): Promise<GetBastionsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Bastion/getBastions:getBastions", {
        "bastionId": args.bastionId,
        "bastionLifecycleState": args.bastionLifecycleState,
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "name": args.name,
    }, opts);
}

/**
 * A collection of arguments for invoking getBastions.
 */
export interface GetBastionsArgs {
    /**
     * The unique identifier (OCID) of the bastion in which to list resources.
     */
    bastionId?: string;
    /**
     * A filter to return only resources their lifecycleState matches the given lifecycleState.
     */
    bastionLifecycleState?: string;
    /**
     * The unique identifier (OCID) of the compartment in which to list resources.
     */
    compartmentId: string;
    filters?: inputs.Bastion.GetBastionsFilter[];
    /**
     * A filter to return only resources that match the entire name given.
     */
    name?: string;
}

/**
 * A collection of values returned by getBastions.
 */
export interface GetBastionsResult {
    readonly bastionId?: string;
    readonly bastionLifecycleState?: string;
    /**
     * The list of bastions.
     */
    readonly bastions: outputs.Bastion.GetBastionsBastion[];
    /**
     * The unique identifier (OCID) of the compartment where the bastion is located.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.Bastion.GetBastionsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The name of the bastion, which can't be changed after creation.
     */
    readonly name?: string;
}
/**
 * This data source provides the list of Bastions in Oracle Cloud Infrastructure Bastion service.
 *
 * Retrieves a list of BastionSummary objects in a compartment. Bastions provide secured, public access to target resources in the cloud that you cannot otherwise reach from the internet.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testBastions = oci.Bastion.getBastions({
 *     compartmentId: compartmentId,
 *     bastionId: testBastion.id,
 *     bastionLifecycleState: bastionBastionLifecycleState,
 *     name: bastionName,
 * });
 * ```
 */
export function getBastionsOutput(args: GetBastionsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetBastionsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Bastion/getBastions:getBastions", {
        "bastionId": args.bastionId,
        "bastionLifecycleState": args.bastionLifecycleState,
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "name": args.name,
    }, opts);
}

/**
 * A collection of arguments for invoking getBastions.
 */
export interface GetBastionsOutputArgs {
    /**
     * The unique identifier (OCID) of the bastion in which to list resources.
     */
    bastionId?: pulumi.Input<string>;
    /**
     * A filter to return only resources their lifecycleState matches the given lifecycleState.
     */
    bastionLifecycleState?: pulumi.Input<string>;
    /**
     * The unique identifier (OCID) of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Bastion.GetBastionsFilterArgs>[]>;
    /**
     * A filter to return only resources that match the entire name given.
     */
    name?: pulumi.Input<string>;
}
