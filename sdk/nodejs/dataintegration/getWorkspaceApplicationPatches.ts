// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Workspace Application Patches in Oracle Cloud Infrastructure Data Integration service.
 *
 * Retrieves a list of patches in an application and provides options to filter the list. For listing changes based on a period and logical objects changed, see ListPatchChanges API.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testWorkspaceApplicationPatches = oci.DataIntegration.getWorkspaceApplicationPatches({
 *     applicationKey: workspaceApplicationPatchApplicationKey,
 *     workspaceId: testWorkspace.id,
 *     fields: workspaceApplicationPatchFields,
 *     identifiers: workspaceApplicationPatchIdentifier,
 *     name: workspaceApplicationPatchName,
 * });
 * ```
 */
export function getWorkspaceApplicationPatches(args: GetWorkspaceApplicationPatchesArgs, opts?: pulumi.InvokeOptions): Promise<GetWorkspaceApplicationPatchesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:DataIntegration/getWorkspaceApplicationPatches:getWorkspaceApplicationPatches", {
        "applicationKey": args.applicationKey,
        "fields": args.fields,
        "filters": args.filters,
        "identifiers": args.identifiers,
        "name": args.name,
        "workspaceId": args.workspaceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getWorkspaceApplicationPatches.
 */
export interface GetWorkspaceApplicationPatchesArgs {
    /**
     * The application key.
     */
    applicationKey: string;
    /**
     * Specifies the fields to get for an object.
     */
    fields?: string[];
    filters?: inputs.DataIntegration.GetWorkspaceApplicationPatchesFilter[];
    /**
     * Used to filter by the identifier of the published object.
     */
    identifiers?: string[];
    /**
     * Used to filter by the name of the object.
     */
    name?: string;
    /**
     * The workspace ID.
     */
    workspaceId: string;
}

/**
 * A collection of values returned by getWorkspaceApplicationPatches.
 */
export interface GetWorkspaceApplicationPatchesResult {
    readonly applicationKey: string;
    readonly fields?: string[];
    readonly filters?: outputs.DataIntegration.GetWorkspaceApplicationPatchesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Value can only contain upper case letters, underscore and numbers. It should begin with upper case letter or underscore. The value can be modified.
     */
    readonly identifiers?: string[];
    /**
     * Free form text without any restriction on permitted characters. Name can have letters, numbers, and special characters. The value is editable and is restricted to 1000 characters.
     */
    readonly name?: string;
    /**
     * The list of patch_summary_collection.
     */
    readonly patchSummaryCollections: outputs.DataIntegration.GetWorkspaceApplicationPatchesPatchSummaryCollection[];
    readonly workspaceId: string;
}
/**
 * This data source provides the list of Workspace Application Patches in Oracle Cloud Infrastructure Data Integration service.
 *
 * Retrieves a list of patches in an application and provides options to filter the list. For listing changes based on a period and logical objects changed, see ListPatchChanges API.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testWorkspaceApplicationPatches = oci.DataIntegration.getWorkspaceApplicationPatches({
 *     applicationKey: workspaceApplicationPatchApplicationKey,
 *     workspaceId: testWorkspace.id,
 *     fields: workspaceApplicationPatchFields,
 *     identifiers: workspaceApplicationPatchIdentifier,
 *     name: workspaceApplicationPatchName,
 * });
 * ```
 */
export function getWorkspaceApplicationPatchesOutput(args: GetWorkspaceApplicationPatchesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetWorkspaceApplicationPatchesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:DataIntegration/getWorkspaceApplicationPatches:getWorkspaceApplicationPatches", {
        "applicationKey": args.applicationKey,
        "fields": args.fields,
        "filters": args.filters,
        "identifiers": args.identifiers,
        "name": args.name,
        "workspaceId": args.workspaceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getWorkspaceApplicationPatches.
 */
export interface GetWorkspaceApplicationPatchesOutputArgs {
    /**
     * The application key.
     */
    applicationKey: pulumi.Input<string>;
    /**
     * Specifies the fields to get for an object.
     */
    fields?: pulumi.Input<pulumi.Input<string>[]>;
    filters?: pulumi.Input<pulumi.Input<inputs.DataIntegration.GetWorkspaceApplicationPatchesFilterArgs>[]>;
    /**
     * Used to filter by the identifier of the published object.
     */
    identifiers?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Used to filter by the name of the object.
     */
    name?: pulumi.Input<string>;
    /**
     * The workspace ID.
     */
    workspaceId: pulumi.Input<string>;
}
