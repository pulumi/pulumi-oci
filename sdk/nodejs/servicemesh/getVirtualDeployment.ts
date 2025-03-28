// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Virtual Deployment resource in Oracle Cloud Infrastructure Service Mesh service.
 *
 * Gets a VirtualDeployment by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVirtualDeployment = oci.ServiceMesh.getVirtualDeployment({
 *     virtualDeploymentId: testVirtualDeploymentOciServiceMeshVirtualDeployment.id,
 * });
 * ```
 */
export function getVirtualDeployment(args: GetVirtualDeploymentArgs, opts?: pulumi.InvokeOptions): Promise<GetVirtualDeploymentResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ServiceMesh/getVirtualDeployment:getVirtualDeployment", {
        "virtualDeploymentId": args.virtualDeploymentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVirtualDeployment.
 */
export interface GetVirtualDeploymentArgs {
    /**
     * Unique VirtualDeployment identifier.
     */
    virtualDeploymentId: string;
}

/**
 * A collection of values returned by getVirtualDeployment.
 */
export interface GetVirtualDeploymentResult {
    /**
     * This configuration determines if logging is enabled and where the logs will be output.
     */
    readonly accessLoggings: outputs.ServiceMesh.GetVirtualDeploymentAccessLogging[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
     */
    readonly description: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * Unique identifier that is immutable on creation.
     */
    readonly id: string;
    /**
     * A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
     */
    readonly lifecycleDetails: string;
    /**
     * The listeners for the virtual deployment
     */
    readonly listeners: outputs.ServiceMesh.GetVirtualDeploymentListener[];
    /**
     * A user-friendly name. The name must be unique within the same virtual service and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
     */
    readonly name: string;
    /**
     * Service Discovery configuration for virtual deployments.
     */
    readonly serviceDiscoveries: outputs.ServiceMesh.GetVirtualDeploymentServiceDiscovery[];
    /**
     * The current state of the Resource.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The time when this resource was created in an RFC3339 formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * The time when this resource was updated in an RFC3339 formatted datetime string.
     */
    readonly timeUpdated: string;
    readonly virtualDeploymentId: string;
    /**
     * The OCID of the virtual service in which this virtual deployment is created.
     */
    readonly virtualServiceId: string;
}
/**
 * This data source provides details about a specific Virtual Deployment resource in Oracle Cloud Infrastructure Service Mesh service.
 *
 * Gets a VirtualDeployment by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testVirtualDeployment = oci.ServiceMesh.getVirtualDeployment({
 *     virtualDeploymentId: testVirtualDeploymentOciServiceMeshVirtualDeployment.id,
 * });
 * ```
 */
export function getVirtualDeploymentOutput(args: GetVirtualDeploymentOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetVirtualDeploymentResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ServiceMesh/getVirtualDeployment:getVirtualDeployment", {
        "virtualDeploymentId": args.virtualDeploymentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getVirtualDeployment.
 */
export interface GetVirtualDeploymentOutputArgs {
    /**
     * Unique VirtualDeployment identifier.
     */
    virtualDeploymentId: pulumi.Input<string>;
}
