// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Deployments in Oracle Cloud Infrastructure API Gateway service.
 *
 * Returns a list of deployments.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDeployments = oci.ApiGateway.getDeployments({
 *     compartmentId: compartmentId,
 *     displayName: deploymentDisplayName,
 *     gatewayId: testGateway.id,
 *     state: deploymentState,
 * });
 * ```
 */
export function getDeployments(args: GetDeploymentsArgs, opts?: pulumi.InvokeOptions): Promise<GetDeploymentsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ApiGateway/getDeployments:getDeployments", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "gatewayId": args.gatewayId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getDeployments.
 */
export interface GetDeploymentsArgs {
    /**
     * The ocid of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
     */
    displayName?: string;
    filters?: inputs.ApiGateway.GetDeploymentsFilter[];
    /**
     * Filter deployments by the gateway ocid.
     */
    gatewayId?: string;
    /**
     * A filter to return only resources that match the given lifecycle state.  Example: `SUCCEEDED`
     */
    state?: string;
}

/**
 * A collection of values returned by getDeployments.
 */
export interface GetDeploymentsResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
     */
    readonly compartmentId: string;
    /**
     * The list of deployment_collection.
     */
    readonly deploymentCollections: outputs.ApiGateway.GetDeploymentsDeploymentCollection[];
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
     */
    readonly displayName?: string;
    readonly filters?: outputs.ApiGateway.GetDeploymentsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     */
    readonly gatewayId?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The current state of the deployment.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Deployments in Oracle Cloud Infrastructure API Gateway service.
 *
 * Returns a list of deployments.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDeployments = oci.ApiGateway.getDeployments({
 *     compartmentId: compartmentId,
 *     displayName: deploymentDisplayName,
 *     gatewayId: testGateway.id,
 *     state: deploymentState,
 * });
 * ```
 */
export function getDeploymentsOutput(args: GetDeploymentsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetDeploymentsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ApiGateway/getDeployments:getDeployments", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "gatewayId": args.gatewayId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getDeployments.
 */
export interface GetDeploymentsOutputArgs {
    /**
     * The ocid of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.ApiGateway.GetDeploymentsFilterArgs>[]>;
    /**
     * Filter deployments by the gateway ocid.
     */
    gatewayId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the given lifecycle state.  Example: `SUCCEEDED`
     */
    state?: pulumi.Input<string>;
}
