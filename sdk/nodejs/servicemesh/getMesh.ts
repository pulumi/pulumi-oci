// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Mesh resource in Oracle Cloud Infrastructure Service Mesh service.
 *
 * Gets a Mesh by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMesh = oci.ServiceMesh.getMesh({
 *     meshId: testMeshOciServiceMeshMesh.id,
 * });
 * ```
 */
export function getMesh(args: GetMeshArgs, opts?: pulumi.InvokeOptions): Promise<GetMeshResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ServiceMesh/getMesh:getMesh", {
        "meshId": args.meshId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMesh.
 */
export interface GetMeshArgs {
    /**
     * Unique Mesh identifier.
     */
    meshId: string;
}

/**
 * A collection of values returned by getMesh.
 */
export interface GetMeshResult {
    /**
     * A list of certificate authority resources to use for creating leaf certificates for mTLS authentication. Currently we only support one certificate authority, but this may expand in future releases. Request with more than one certificate authority will be rejected.
     */
    readonly certificateAuthorities: outputs.ServiceMesh.GetMeshCertificateAuthority[];
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
     * A user-friendly name. The name does not have to be unique and can be changed after creation. Avoid entering confidential information.  Example: `My new resource`
     */
    readonly displayName: string;
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
    readonly meshId: string;
    /**
     * Sets a minimum level of mTLS authentication for all virtual services within the mesh.
     */
    readonly mtls: outputs.ServiceMesh.GetMeshMtl[];
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
}
/**
 * This data source provides details about a specific Mesh resource in Oracle Cloud Infrastructure Service Mesh service.
 *
 * Gets a Mesh by identifier.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMesh = oci.ServiceMesh.getMesh({
 *     meshId: testMeshOciServiceMeshMesh.id,
 * });
 * ```
 */
export function getMeshOutput(args: GetMeshOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetMeshResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ServiceMesh/getMesh:getMesh", {
        "meshId": args.meshId,
    }, opts);
}

/**
 * A collection of arguments for invoking getMesh.
 */
export interface GetMeshOutputArgs {
    /**
     * Unique Mesh identifier.
     */
    meshId: pulumi.Input<string>;
}
