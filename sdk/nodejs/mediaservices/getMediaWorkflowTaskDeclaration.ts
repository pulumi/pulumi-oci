// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Media Workflow Task Declaration resource in Oracle Cloud Infrastructure Media Services service.
 *
 * Returns a list of MediaWorkflowTaskDeclarations.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMediaWorkflowTaskDeclaration = oci.MediaServices.getMediaWorkflowTaskDeclaration({
 *     compartmentId: _var.compartment_id,
 *     isCurrent: _var.media_workflow_task_declaration_is_current,
 *     name: _var.media_workflow_task_declaration_name,
 *     version: _var.media_workflow_task_declaration_version,
 * });
 * ```
 */
export function getMediaWorkflowTaskDeclaration(args?: GetMediaWorkflowTaskDeclarationArgs, opts?: pulumi.InvokeOptions): Promise<GetMediaWorkflowTaskDeclarationResult> {
    args = args || {};

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:MediaServices/getMediaWorkflowTaskDeclaration:getMediaWorkflowTaskDeclaration", {
        "compartmentId": args.compartmentId,
        "isCurrent": args.isCurrent,
        "name": args.name,
        "version": args.version,
    }, opts);
}

/**
 * A collection of arguments for invoking getMediaWorkflowTaskDeclaration.
 */
export interface GetMediaWorkflowTaskDeclarationArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId?: string;
    /**
     * A filter to only select the newest version for each MediaWorkflowTaskDeclaration name.
     */
    isCurrent?: boolean;
    /**
     * A filter to return only the resources with their system defined, unique name matching the given name.
     */
    name?: string;
    /**
     * A filter to select MediaWorkflowTaskDeclaration by version.
     */
    version?: number;
}

/**
 * A collection of values returned by getMediaWorkflowTaskDeclaration.
 */
export interface GetMediaWorkflowTaskDeclarationResult {
    readonly compartmentId?: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    readonly isCurrent?: boolean;
    /**
     * List of MediaWorkflowTaskDeclaration objects.
     */
    readonly items: outputs.MediaServices.GetMediaWorkflowTaskDeclarationItem[];
    /**
     * MediaWorkflowTaskDeclaration identifier. The name and version should be unique among MediaWorkflowTaskDeclarations.
     */
    readonly name?: string;
    /**
     * The version of MediaWorkflowTaskDeclaration, incremented whenever the team implementing the task processor modifies the JSON schema of this declaration's definitions, parameters or list of required parameters.
     */
    readonly version?: number;
}
/**
 * This data source provides details about a specific Media Workflow Task Declaration resource in Oracle Cloud Infrastructure Media Services service.
 *
 * Returns a list of MediaWorkflowTaskDeclarations.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testMediaWorkflowTaskDeclaration = oci.MediaServices.getMediaWorkflowTaskDeclaration({
 *     compartmentId: _var.compartment_id,
 *     isCurrent: _var.media_workflow_task_declaration_is_current,
 *     name: _var.media_workflow_task_declaration_name,
 *     version: _var.media_workflow_task_declaration_version,
 * });
 * ```
 */
export function getMediaWorkflowTaskDeclarationOutput(args?: GetMediaWorkflowTaskDeclarationOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetMediaWorkflowTaskDeclarationResult> {
    return pulumi.output(args).apply((a: any) => getMediaWorkflowTaskDeclaration(a, opts))
}

/**
 * A collection of arguments for invoking getMediaWorkflowTaskDeclaration.
 */
export interface GetMediaWorkflowTaskDeclarationOutputArgs {
    /**
     * The ID of the compartment in which to list resources.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * A filter to only select the newest version for each MediaWorkflowTaskDeclaration name.
     */
    isCurrent?: pulumi.Input<boolean>;
    /**
     * A filter to return only the resources with their system defined, unique name matching the given name.
     */
    name?: pulumi.Input<string>;
    /**
     * A filter to select MediaWorkflowTaskDeclaration by version.
     */
    version?: pulumi.Input<number>;
}