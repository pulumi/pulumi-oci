// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Endpoints in Oracle Cloud Infrastructure Ai Language service.
 *
 * Returns a list of Endpoints.
 */
export function getEndpoints(args: GetEndpointsArgs, opts?: pulumi.InvokeOptions): Promise<GetEndpointsResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:AiLanguage/getEndpoints:getEndpoints", {
        "compartmentId": args.compartmentId,
        "displayName": args.displayName,
        "filters": args.filters,
        "id": args.id,
        "modelId": args.modelId,
        "projectId": args.projectId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getEndpoints.
 */
export interface GetEndpointsArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: string;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: string;
    filters?: inputs.AiLanguage.GetEndpointsFilter[];
    /**
     * Unique identifier endpoint OCID of an endpoint that is immutable on creation.
     */
    id?: string;
    /**
     * The ID of the trained model for which to list the endpoints.
     */
    modelId?: string;
    /**
     * The ID of the project for which to list the objects.
     */
    projectId?: string;
    /**
     * <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
     */
    state?: string;
}

/**
 * A collection of values returned by getEndpoints.
 */
export interface GetEndpointsResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the endpoint compartment.
     */
    readonly compartmentId: string;
    /**
     * A user-friendly display name for the resource. It should be unique and can be modified. Avoid entering confidential information.
     */
    readonly displayName?: string;
    /**
     * The list of endpoint_collection.
     */
    readonly endpointCollections: outputs.AiLanguage.GetEndpointsEndpointCollection[];
    readonly filters?: outputs.AiLanguage.GetEndpointsFilter[];
    /**
     * Unique identifier endpoint OCID of an endpoint that is immutable on creation.
     */
    readonly id?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model to associate with the endpoint.
     */
    readonly modelId?: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the Endpoint.
     */
    readonly projectId?: string;
    /**
     * The state of the endpoint.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Endpoints in Oracle Cloud Infrastructure Ai Language service.
 *
 * Returns a list of Endpoints.
 */
export function getEndpointsOutput(args: GetEndpointsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetEndpointsResult> {
    return pulumi.output(args).apply((a: any) => getEndpoints(a, opts))
}

/**
 * A collection of arguments for invoking getEndpoints.
 */
export interface GetEndpointsOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * A filter to return only resources that match the entire display name given.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.AiLanguage.GetEndpointsFilterArgs>[]>;
    /**
     * Unique identifier endpoint OCID of an endpoint that is immutable on creation.
     */
    id?: pulumi.Input<string>;
    /**
     * The ID of the trained model for which to list the endpoints.
     */
    modelId?: pulumi.Input<string>;
    /**
     * The ID of the project for which to list the objects.
     */
    projectId?: pulumi.Input<string>;
    /**
     * <b>Filter</b> results by the specified lifecycle state. Must be a valid state for the resource type.
     */
    state?: pulumi.Input<string>;
}