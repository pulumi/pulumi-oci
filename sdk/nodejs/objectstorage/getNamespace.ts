// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Namespace resource in Oracle Cloud Infrastructure Object Storage service.
 *
 * Each Oracle Cloud Infrastructure tenant is assigned one unique and uneditable Object Storage namespace. The namespace
 * is a system-generated string assigned during account creation. For some older tenancies, the namespace string may be
 * the tenancy name in all lower-case letters. You cannot edit a namespace.
 *
 * GetNamespace returns the name of the Object Storage namespace for the user making the request.
 * If an optional compartmentId query parameter is provided, GetNamespace returns the namespace name of the corresponding
 * tenancy, provided the user has access to it.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNamespace = oci.ObjectStorage.getNamespace({
 *     compartmentId: compartmentId,
 * });
 * ```
 */
export function getNamespace(args?: GetNamespaceArgs, opts?: pulumi.InvokeOptions): Promise<GetNamespaceResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:ObjectStorage/getNamespace:getNamespace", {
        "compartmentId": args.compartmentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getNamespace.
 */
export interface GetNamespaceArgs {
    /**
     * This is an optional field representing either the tenancy [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) or the compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) within the tenancy whose Object Storage namespace is to be retrieved.
     */
    compartmentId?: string;
}

/**
 * A collection of values returned by getNamespace.
 */
export interface GetNamespaceResult {
    readonly compartmentId?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * (Computed) The name of the user's namespace.
     */
    readonly namespace: string;
}
/**
 * This data source provides details about a specific Namespace resource in Oracle Cloud Infrastructure Object Storage service.
 *
 * Each Oracle Cloud Infrastructure tenant is assigned one unique and uneditable Object Storage namespace. The namespace
 * is a system-generated string assigned during account creation. For some older tenancies, the namespace string may be
 * the tenancy name in all lower-case letters. You cannot edit a namespace.
 *
 * GetNamespace returns the name of the Object Storage namespace for the user making the request.
 * If an optional compartmentId query parameter is provided, GetNamespace returns the namespace name of the corresponding
 * tenancy, provided the user has access to it.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testNamespace = oci.ObjectStorage.getNamespace({
 *     compartmentId: compartmentId,
 * });
 * ```
 */
export function getNamespaceOutput(args?: GetNamespaceOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetNamespaceResult> {
    args = args || {};
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:ObjectStorage/getNamespace:getNamespace", {
        "compartmentId": args.compartmentId,
    }, opts);
}

/**
 * A collection of arguments for invoking getNamespace.
 */
export interface GetNamespaceOutputArgs {
    /**
     * This is an optional field representing either the tenancy [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) or the compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) within the tenancy whose Object Storage namespace is to be retrieved.
     */
    compartmentId?: pulumi.Input<string>;
}
