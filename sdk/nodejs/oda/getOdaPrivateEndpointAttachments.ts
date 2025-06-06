// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Oda Private Endpoint Attachments in Oracle Cloud Infrastructure Digital Assistant service.
 *
 * Returns a page of ODA Instances attached to this ODA Private Endpoint.
 *
 * If the `opc-next-page` header appears in the response, then
 * there are more items to retrieve. To get the next page in the subsequent
 * GET request, include the header's value as the `page` query parameter.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOdaPrivateEndpointAttachments = oci.Oda.getOdaPrivateEndpointAttachments({
 *     compartmentId: compartmentId,
 *     odaPrivateEndpointId: testOdaPrivateEndpoint.id,
 *     state: odaPrivateEndpointAttachmentState,
 * });
 * ```
 */
export function getOdaPrivateEndpointAttachments(args: GetOdaPrivateEndpointAttachmentsArgs, opts?: pulumi.InvokeOptions): Promise<GetOdaPrivateEndpointAttachmentsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Oda/getOdaPrivateEndpointAttachments:getOdaPrivateEndpointAttachments", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "odaPrivateEndpointId": args.odaPrivateEndpointId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getOdaPrivateEndpointAttachments.
 */
export interface GetOdaPrivateEndpointAttachmentsArgs {
    /**
     * List the ODA Private Endpoint Attachments that belong to this compartment.
     */
    compartmentId: string;
    filters?: inputs.Oda.GetOdaPrivateEndpointAttachmentsFilter[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of ODA Private Endpoint.
     */
    odaPrivateEndpointId: string;
    /**
     * List only the ODA Private Endpoint Attachments that are in this lifecycle state.
     */
    state?: string;
}

/**
 * A collection of values returned by getOdaPrivateEndpointAttachments.
 */
export interface GetOdaPrivateEndpointAttachmentsResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that the ODA private endpoint attachment belongs to.
     */
    readonly compartmentId: string;
    readonly filters?: outputs.Oda.GetOdaPrivateEndpointAttachmentsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of oda_private_endpoint_attachment_collection.
     */
    readonly odaPrivateEndpointAttachmentCollections: outputs.Oda.GetOdaPrivateEndpointAttachmentsOdaPrivateEndpointAttachmentCollection[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ODA Private Endpoint.
     */
    readonly odaPrivateEndpointId: string;
    /**
     * The current state of the ODA Private Endpoint attachment.
     */
    readonly state?: string;
}
/**
 * This data source provides the list of Oda Private Endpoint Attachments in Oracle Cloud Infrastructure Digital Assistant service.
 *
 * Returns a page of ODA Instances attached to this ODA Private Endpoint.
 *
 * If the `opc-next-page` header appears in the response, then
 * there are more items to retrieve. To get the next page in the subsequent
 * GET request, include the header's value as the `page` query parameter.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOdaPrivateEndpointAttachments = oci.Oda.getOdaPrivateEndpointAttachments({
 *     compartmentId: compartmentId,
 *     odaPrivateEndpointId: testOdaPrivateEndpoint.id,
 *     state: odaPrivateEndpointAttachmentState,
 * });
 * ```
 */
export function getOdaPrivateEndpointAttachmentsOutput(args: GetOdaPrivateEndpointAttachmentsOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetOdaPrivateEndpointAttachmentsResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Oda/getOdaPrivateEndpointAttachments:getOdaPrivateEndpointAttachments", {
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "odaPrivateEndpointId": args.odaPrivateEndpointId,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getOdaPrivateEndpointAttachments.
 */
export interface GetOdaPrivateEndpointAttachmentsOutputArgs {
    /**
     * List the ODA Private Endpoint Attachments that belong to this compartment.
     */
    compartmentId: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.Oda.GetOdaPrivateEndpointAttachmentsFilterArgs>[]>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of ODA Private Endpoint.
     */
    odaPrivateEndpointId: pulumi.Input<string>;
    /**
     * List only the ODA Private Endpoint Attachments that are in this lifecycle state.
     */
    state?: pulumi.Input<string>;
}
