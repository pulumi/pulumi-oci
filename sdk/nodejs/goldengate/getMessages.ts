// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Messages in Oracle Cloud Infrastructure Golden Gate service.
 *
 * Lists the DeploymentMessages for a deployment. The sorting order is not important. By default first will be Upgrade message, next Exception message and then Storage Utilization message.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMessages = oci.GoldenGate.getMessages({
 *     deploymentId: oci_golden_gate_deployment.test_deployment.id,
 * });
 * ```
 */
export function getMessages(args: GetMessagesArgs, opts?: pulumi.InvokeOptions): Promise<GetMessagesResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:GoldenGate/getMessages:getMessages", {
        "deploymentId": args.deploymentId,
        "filters": args.filters,
    }, opts);
}

/**
 * A collection of arguments for invoking getMessages.
 */
export interface GetMessagesArgs {
    /**
     * A unique Deployment identifier.
     */
    deploymentId: string;
    filters?: inputs.GoldenGate.GetMessagesFilter[];
}

/**
 * A collection of values returned by getMessages.
 */
export interface GetMessagesResult {
    readonly deploymentId: string;
    /**
     * The list of deployment_messages_collection.
     */
    readonly deploymentMessagesCollections: outputs.GoldenGate.GetMessagesDeploymentMessagesCollection[];
    readonly filters?: outputs.GoldenGate.GetMessagesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
}
/**
 * This data source provides the list of Messages in Oracle Cloud Infrastructure Golden Gate service.
 *
 * Lists the DeploymentMessages for a deployment. The sorting order is not important. By default first will be Upgrade message, next Exception message and then Storage Utilization message.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMessages = oci.GoldenGate.getMessages({
 *     deploymentId: oci_golden_gate_deployment.test_deployment.id,
 * });
 * ```
 */
export function getMessagesOutput(args: GetMessagesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetMessagesResult> {
    return pulumi.output(args).apply((a: any) => getMessages(a, opts))
}

/**
 * A collection of arguments for invoking getMessages.
 */
export interface GetMessagesOutputArgs {
    /**
     * A unique Deployment identifier.
     */
    deploymentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.GoldenGate.GetMessagesFilterArgs>[]>;
}