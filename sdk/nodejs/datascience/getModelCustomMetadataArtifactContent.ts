// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Model Custom Metadata Artifact Content resource in Oracle Cloud Infrastructure Data Science service.
 *
 * Downloads model custom metadata artifact content for specified model metadata key.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testModelCustomMetadataArtifactContent = oci.DataScience.getModelCustomMetadataArtifactContent({
 *     metadatumKeyName: testKey.name,
 *     modelId: testModel.id,
 *     range: modelCustomMetadataArtifactContentRange,
 * });
 * ```
 */
export function getModelCustomMetadataArtifactContent(args: GetModelCustomMetadataArtifactContentArgs, opts?: pulumi.InvokeOptions): Promise<GetModelCustomMetadataArtifactContentResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataScience/getModelCustomMetadataArtifactContent:getModelCustomMetadataArtifactContent", {
        "metadatumKeyName": args.metadatumKeyName,
        "modelId": args.modelId,
        "range": args.range,
    }, opts);
}

/**
 * A collection of arguments for invoking getModelCustomMetadataArtifactContent.
 */
export interface GetModelCustomMetadataArtifactContentArgs {
    /**
     * The name of the model metadatum in the metadata.
     */
    metadatumKeyName: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
     */
    modelId: string;
    /**
     * Optional byte range to fetch, as described in [RFC 7233](https://tools.ietf.org/html/rfc7232#section-2.1), section 2.1. Note that only a single range of bytes is supported.
     */
    range?: string;
}

/**
 * A collection of values returned by getModelCustomMetadataArtifactContent.
 */
export interface GetModelCustomMetadataArtifactContentResult {
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly metadatumKeyName: string;
    readonly modelId: string;
    readonly range?: string;
}
/**
 * This data source provides details about a specific Model Custom Metadata Artifact Content resource in Oracle Cloud Infrastructure Data Science service.
 *
 * Downloads model custom metadata artifact content for specified model metadata key.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testModelCustomMetadataArtifactContent = oci.DataScience.getModelCustomMetadataArtifactContent({
 *     metadatumKeyName: testKey.name,
 *     modelId: testModel.id,
 *     range: modelCustomMetadataArtifactContentRange,
 * });
 * ```
 */
export function getModelCustomMetadataArtifactContentOutput(args: GetModelCustomMetadataArtifactContentOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetModelCustomMetadataArtifactContentResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataScience/getModelCustomMetadataArtifactContent:getModelCustomMetadataArtifactContent", {
        "metadatumKeyName": args.metadatumKeyName,
        "modelId": args.modelId,
        "range": args.range,
    }, opts);
}

/**
 * A collection of arguments for invoking getModelCustomMetadataArtifactContent.
 */
export interface GetModelCustomMetadataArtifactContentOutputArgs {
    /**
     * The name of the model metadatum in the metadata.
     */
    metadatumKeyName: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the model.
     */
    modelId: pulumi.Input<string>;
    /**
     * Optional byte range to fetch, as described in [RFC 7233](https://tools.ietf.org/html/rfc7232#section-2.1), section 2.1. Note that only a single range of bytes is supported.
     */
    range?: pulumi.Input<string>;
}
