// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Ingress Gateways in Oracle Cloud Infrastructure Service Mesh service.
 *
 * Returns a list of IngressGateway objects.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testIngressGateways = oci.ServiceMesh.getIngressGateways({
 *     compartmentId: _var.compartment_id,
 *     id: _var.ingress_gateway_id,
 *     meshId: oci_service_mesh_mesh.test_mesh.id,
 *     name: _var.ingress_gateway_name,
 *     state: _var.ingress_gateway_state,
 * });
 * ```
 */
export function getIngressGateways(args: GetIngressGatewaysArgs, opts?: pulumi.InvokeOptions): Promise<GetIngressGatewaysResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:ServiceMesh/getIngressGateways:getIngressGateways", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "id": args.id,
        "meshId": args.meshId,
        "name": args.name,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getIngressGateways.
 */
export interface GetIngressGatewaysArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    filters?: inputs.ServiceMesh.GetIngressGatewaysFilter[];
    /**
     * Unique IngressGateway identifier.
     */
    id?: string;
    /**
     * Unique Mesh identifier.
     */
    meshId?: string;
    /**
     * A filter to return only resources that match the entire name given.
     */
    name?: string;
    /**
     * A filter to return only resources that match the life cycle state given.
     */
    state?: string;
}

/**
 * A collection of values returned by getIngressGateways.
 */
export interface GetIngressGatewaysResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.ServiceMesh.GetIngressGatewaysFilter[];
    /**
     * Unique identifier that is immutable on creation.
     */
    readonly id?: string;
    /**
     * The list of ingress_gateway_collection.
     */
    readonly ingressGatewayCollections: outputs.ServiceMesh.GetIngressGatewaysIngressGatewayCollection[];
    /**
     * The OCID of the service mesh in which this ingress gateway is created.
     */
    readonly meshId?: string;
    /**
     * A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
     */
    readonly name?: string;
    /**
     * The current state of the Resource.
     */
    readonly state?: string;
}

export function getIngressGatewaysOutput(args: GetIngressGatewaysOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetIngressGatewaysResult> {
    return pulumi.output(args).apply(a => getIngressGateways(a, opts))
}

/**
 * A collection of arguments for invoking getIngressGateways.
 */
export interface GetIngressGatewaysOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.ServiceMesh.GetIngressGatewaysFilterArgs>[]>;
    /**
     * Unique IngressGateway identifier.
     */
    id?: pulumi.Input<string>;
    /**
     * Unique Mesh identifier.
     */
    meshId?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire name given.
     */
    name?: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the life cycle state given.
     */
    state?: pulumi.Input<string>;
}