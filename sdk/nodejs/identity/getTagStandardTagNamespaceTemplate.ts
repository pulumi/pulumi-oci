// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Tag Standard Tag Namespace Template resource in Oracle Cloud Infrastructure Identity service.
 *
 * Retrieve the standard tag namespace template given the standard tag namespace name.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testTagStandardTagNamespaceTemplate = oci.Identity.getTagStandardTagNamespaceTemplate({
 *     compartmentId: _var.compartment_id,
 *     standardTagNamespaceName: oci_identity_tag_namespace.test_tag_namespace.name,
 * });
 * ```
 */
export function getTagStandardTagNamespaceTemplate(args: GetTagStandardTagNamespaceTemplateArgs, opts?: pulumi.InvokeOptions): Promise<GetTagStandardTagNamespaceTemplateResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:Identity/getTagStandardTagNamespaceTemplate:getTagStandardTagNamespaceTemplate", {
        "compartmentId": args.compartmentId,
        "standardTagNamespaceName": args.standardTagNamespaceName,
    }, opts);
}

/**
 * A collection of arguments for invoking getTagStandardTagNamespaceTemplate.
 */
export interface GetTagStandardTagNamespaceTemplateArgs {
    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     */
    compartmentId: string;
    /**
     * The name of the standard tag namespace tempate that is requested
     */
    standardTagNamespaceName: string;
}

/**
 * A collection of values returned by getTagStandardTagNamespaceTemplate.
 */
export interface GetTagStandardTagNamespaceTemplateResult {
    readonly compartmentId: string;
    /**
     * The default description of the tag namespace that users can use to create the tag definition
     */
    readonly description: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The reserved name of this standard tag namespace
     */
    readonly standardTagNamespaceName: string;
    /**
     * The status of the standard tag namespace
     */
    readonly status: string;
    /**
     * The template of the tag definition. This object includes necessary details to create the provided standard tag definition.
     */
    readonly tagDefinitionTemplates: outputs.Identity.GetTagStandardTagNamespaceTemplateTagDefinitionTemplate[];
}

export function getTagStandardTagNamespaceTemplateOutput(args: GetTagStandardTagNamespaceTemplateOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetTagStandardTagNamespaceTemplateResult> {
    return pulumi.output(args).apply(a => getTagStandardTagNamespaceTemplate(a, opts))
}

/**
 * A collection of arguments for invoking getTagStandardTagNamespaceTemplate.
 */
export interface GetTagStandardTagNamespaceTemplateOutputArgs {
    /**
     * The OCID of the compartment (remember that the tenancy is simply the root compartment).
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The name of the standard tag namespace tempate that is requested
     */
    standardTagNamespaceName: pulumi.Input<string>;
}