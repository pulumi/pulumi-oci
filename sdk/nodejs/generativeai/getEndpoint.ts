// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Endpoint resource in Oracle Cloud Infrastructure Generative AI service.
 *
 * Gets information about an endpoint.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testEndpoint = oci.GenerativeAi.getEndpoint({
 *     endpointId: testEndpointOciGenerativeAiEndpoint.id,
 * });
 * ```
 */
export function getEndpoint(args: GetEndpointArgs, opts?: pulumi.InvokeOptions): Promise<GetEndpointResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:GenerativeAi/getEndpoint:getEndpoint", {
        "endpointId": args.endpointId,
    }, opts);
}

/**
 * A collection of arguments for invoking getEndpoint.
 */
export interface GetEndpointArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the endpoint.
     */
    endpointId: string;
}

/**
 * A collection of values returned by getEndpoint.
 */
export interface GetEndpointResult {
    readonly compartmentId: string;
    readonly contentModerationConfigs: outputs.GenerativeAi.GetEndpointContentModerationConfig[];
    readonly dedicatedAiClusterId: string;
    readonly definedTags: {[key: string]: string};
    /**
     * An optional description of the endpoint.
     */
    readonly description: string;
    /**
     * A user-friendly name. Does not have to be unique, and it's changeable.
     */
    readonly displayName: string;
    readonly endpointId: string;
    readonly freeformTags: {[key: string]: string};
    readonly id: string;
    readonly lifecycleDetails: string;
    /**
     * The OCID of the model that's used to create this endpoint.
     */
    readonly modelId: string;
    /**
     * The current state of the endpoint.
     */
    readonly state: string;
    readonly systemTags: {[key: string]: string};
    readonly timeCreated: string;
    /**
     * The date and time that the endpoint was updated in the format of an RFC3339 datetime string.
     */
    readonly timeUpdated: string;
}
/**
 * This data source provides details about a specific Endpoint resource in Oracle Cloud Infrastructure Generative AI service.
 *
 * Gets information about an endpoint.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testEndpoint = oci.GenerativeAi.getEndpoint({
 *     endpointId: testEndpointOciGenerativeAiEndpoint.id,
 * });
 * ```
 */
export function getEndpointOutput(args: GetEndpointOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetEndpointResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:GenerativeAi/getEndpoint:getEndpoint", {
        "endpointId": args.endpointId,
    }, opts);
}

/**
 * A collection of arguments for invoking getEndpoint.
 */
export interface GetEndpointOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the endpoint.
     */
    endpointId: pulumi.Input<string>;
}
