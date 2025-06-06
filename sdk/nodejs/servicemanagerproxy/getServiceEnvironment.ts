// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Service Environment resource in Oracle Cloud Infrastructure Service Manager Proxy service.
 *
 * Get the detailed information for a specific service environment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testServiceEnvironment = oci.ServiceManagerProxy.getServiceEnvironment({
 *     compartmentId: compartmentId,
 *     serviceEnvironmentId: testServiceEnvironmentOciServiceManagerProxyServiceEnvironment.id,
 * });
 * ```
 */
export function getServiceEnvironment(args: GetServiceEnvironmentArgs, opts?: pulumi.InvokeOptions): Promise<GetServiceEnvironmentResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ServiceManagerProxy/getServiceEnvironment:getServiceEnvironment", {
        "compartmentId": args.compartmentId,
        "serviceEnvironmentId": args.serviceEnvironmentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getServiceEnvironment.
 */
export interface GetServiceEnvironmentArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment.
     */
    compartmentId: string;
    /**
     * The unique identifier associated with the service environment. 
     *
     * **Note:** Not an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    serviceEnvironmentId: string;
}

/**
 * A collection of values returned by getServiceEnvironment.
 */
export interface GetServiceEnvironmentResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment.
     */
    readonly compartmentId: string;
    /**
     * The URL for the console.
     */
    readonly consoleUrl: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Details for a service definition.
     */
    readonly serviceDefinitions: outputs.ServiceManagerProxy.GetServiceEnvironmentServiceDefinition[];
    /**
     * Array of service environment end points.
     */
    readonly serviceEnvironmentEndpoints: outputs.ServiceManagerProxy.GetServiceEnvironmentServiceEnvironmentEndpoint[];
    readonly serviceEnvironmentId: string;
    /**
     * Status of the entitlement registration for the service.
     */
    readonly status: string;
    /**
     * The unique subscription ID associated with the service environment ID.
     */
    readonly subscriptionId: string;
}
/**
 * This data source provides details about a specific Service Environment resource in Oracle Cloud Infrastructure Service Manager Proxy service.
 *
 * Get the detailed information for a specific service environment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testServiceEnvironment = oci.ServiceManagerProxy.getServiceEnvironment({
 *     compartmentId: compartmentId,
 *     serviceEnvironmentId: testServiceEnvironmentOciServiceManagerProxyServiceEnvironment.id,
 * });
 * ```
 */
export function getServiceEnvironmentOutput(args: GetServiceEnvironmentOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetServiceEnvironmentResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ServiceManagerProxy/getServiceEnvironment:getServiceEnvironment", {
        "compartmentId": args.compartmentId,
        "serviceEnvironmentId": args.serviceEnvironmentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getServiceEnvironment.
 */
export interface GetServiceEnvironmentOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The unique identifier associated with the service environment. 
     *
     * **Note:** Not an [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    serviceEnvironmentId: pulumi.Input<string>;
}
