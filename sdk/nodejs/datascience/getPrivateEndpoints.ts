// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Data Science Private Endpoints in Oracle Cloud Infrastructure Data Science service.
 *
 * Lists all Data Science private endpoints in the specified compartment. The query must include compartmentId. The query can also include one other parameter. If the query doesn't include compartmentId, or includes compartmentId with two or more other parameters, then an error is returned.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataSciencePrivateEndpoints = oci.DataScience.getPrivateEndpoints({
 *     compartmentId: compartmentId,
 *     createdBy: dataSciencePrivateEndpointCreatedBy,
 *     dataScienceResourceType: dataSciencePrivateEndpointDataScienceResourceType,
 *     displayName: dataSciencePrivateEndpointDisplayName,
 *     state: dataSciencePrivateEndpointState,
 * });
 * ```
 */
export function getPrivateEndpoints(args: GetPrivateEndpointsArgs, opts?: pulumi.InvokeOptions): Promise<GetPrivateEndpointsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataScience/getPrivateEndpoints:getPrivateEndpoints", {
        "compartmentId": args.compartmentId,
        "createdBy": args.createdBy,
        "dataScienceResourceType": args.dataScienceResourceType,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getPrivateEndpoints.
 */
export interface GetPrivateEndpointsArgs {
    /**
     * <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
     */
    createdBy?: string;
    /**
     * Resource types in the Data Science service such as notebooks.
     */
    dataScienceResourceType?: string;
    /**
     * <b>Filter</b> results by its user-friendly name.
     */
    displayName?: string;
    filters?: inputs.DataScience.GetPrivateEndpointsFilter[];
    /**
     * The lifecycle state of the private endpoint.
     */
    state?: string;
}

/**
 * A collection of values returned by getPrivateEndpoints.
 */
export interface GetPrivateEndpointsResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment where you want to create private endpoint.
     */
    readonly compartmentId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user that created the private endpoint.
     */
    readonly createdBy?: string;
    /**
     * The list of data_science_private_endpoints.
     */
    readonly dataSciencePrivateEndpoints: outputs.DataScience.GetPrivateEndpointsDataSciencePrivateEndpoint[];
    /**
     * Data Science resource type.
     */
    readonly dataScienceResourceType?: string;
    /**
     * A user friendly name. It doesn't have to be unique. Avoid entering confidential information.
     */
    readonly displayName?: string;
    readonly filters?: outputs.DataScience.GetPrivateEndpointsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * State of the Data Science private endpoint.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Data Science Private Endpoints in Oracle Cloud Infrastructure Data Science service.
 *
 * Lists all Data Science private endpoints in the specified compartment. The query must include compartmentId. The query can also include one other parameter. If the query doesn't include compartmentId, or includes compartmentId with two or more other parameters, then an error is returned.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testDataSciencePrivateEndpoints = oci.DataScience.getPrivateEndpoints({
 *     compartmentId: compartmentId,
 *     createdBy: dataSciencePrivateEndpointCreatedBy,
 *     dataScienceResourceType: dataSciencePrivateEndpointDataScienceResourceType,
 *     displayName: dataSciencePrivateEndpointDisplayName,
 *     state: dataSciencePrivateEndpointState,
 * });
 * ```
 */
export function getPrivateEndpointsOutput(args: GetPrivateEndpointsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetPrivateEndpointsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataScience/getPrivateEndpoints:getPrivateEndpoints", {
        "compartmentId": args.compartmentId,
        "createdBy": args.createdBy,
        "dataScienceResourceType": args.dataScienceResourceType,
        "displayName": args.displayName,
        "filters": args.filters,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getPrivateEndpoints.
 */
export interface GetPrivateEndpointsOutputArgs {
    /**
     * <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * <b>Filter</b> results by the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user who created the resource.
     */
    createdBy?: pulumi.Input<string>;
    /**
     * Resource types in the Data Science service such as notebooks.
     */
    dataScienceResourceType?: pulumi.Input<string>;
    /**
     * <b>Filter</b> results by its user-friendly name.
     */
    displayName?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataScience.GetPrivateEndpointsFilterArgs>[]>;
    /**
     * The lifecycle state of the private endpoint.
     */
    state?: pulumi.Input<string>;
}
