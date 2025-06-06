// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Container Image Signature resource in Oracle Cloud Infrastructure Artifacts service.
 *
 * Get container image signature metadata.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testContainerImageSignature = oci.Artifacts.getContainerImageSignature({
 *     imageSignatureId: testImageSignature.id,
 * });
 * ```
 */
export function getContainerImageSignature(args: GetContainerImageSignatureArgs, opts?: pulumi.InvokeOptions): Promise<GetContainerImageSignatureResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Artifacts/getContainerImageSignature:getContainerImageSignature", {
        "imageSignatureId": args.imageSignatureId,
    }, opts);
}

/**
 * A collection of arguments for invoking getContainerImageSignature.
 */
export interface GetContainerImageSignatureArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image signature.  Example: `ocid1.containersignature.oc1..exampleuniqueID`
     */
    imageSignatureId: string;
}

/**
 * A collection of values returned by getContainerImageSignature.
 */
export interface GetContainerImageSignatureResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the container repository exists.
     */
    readonly compartmentId: string;
    /**
     * The id of the user or principal that created the resource.
     */
    readonly createdBy: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * The last 10 characters of the kmsKeyId, the last 10 characters of the kmsKeyVersionId, the signingAlgorithm, and the last 10 characters of the signatureId.  Example: `wrmz22sixa::qdwyc2ptun::SHA_256_RSA_PKCS_PSS::2vwmobasva`
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image signature.  Example: `ocid1.containerimagesignature.oc1..exampleuniqueID`
     */
    readonly id: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image.  Example: `ocid1.containerimage.oc1..exampleuniqueID`
     */
    readonly imageId: string;
    readonly imageSignatureId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the kmsKeyId used to sign the container image.  Example: `ocid1.key.oc1..exampleuniqueID`
     */
    readonly kmsKeyId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the kmsKeyVersionId used to sign the container image.  Example: `ocid1.keyversion.oc1..exampleuniqueID`
     */
    readonly kmsKeyVersionId: string;
    /**
     * The base64 encoded signature payload that was signed.
     */
    readonly message: string;
    /**
     * The signature of the message field using the kmsKeyId, the kmsKeyVersionId, and the signingAlgorithm.
     */
    readonly signature: string;
    /**
     * The algorithm to be used for signing. These are the only supported signing algorithms for container images.
     */
    readonly signingAlgorithm: string;
    /**
     * The current state of the container image signature.
     */
    readonly state: string;
    /**
     * The system tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * An RFC 3339 timestamp indicating when the image was created.
     */
    readonly timeCreated: string;
}
/**
 * This data source provides details about a specific Container Image Signature resource in Oracle Cloud Infrastructure Artifacts service.
 *
 * Get container image signature metadata.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testContainerImageSignature = oci.Artifacts.getContainerImageSignature({
 *     imageSignatureId: testImageSignature.id,
 * });
 * ```
 */
export function getContainerImageSignatureOutput(args: GetContainerImageSignatureOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetContainerImageSignatureResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Artifacts/getContainerImageSignature:getContainerImageSignature", {
        "imageSignatureId": args.imageSignatureId,
    }, opts);
}

/**
 * A collection of arguments for invoking getContainerImageSignature.
 */
export interface GetContainerImageSignatureOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container image signature.  Example: `ocid1.containersignature.oc1..exampleuniqueID`
     */
    imageSignatureId: pulumi.Input<string>;
}
