// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Software Source Module Streams in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Lists module streams from the specified software source OCID. Filter the list against a variety of
 * criteria including but not limited to its module name and (stream) name.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSoftwareSourceModuleStreams = oci.OsManagementHub.getSoftwareSourceModuleStreams({
 *     softwareSourceId: oci_os_management_hub_software_source.test_software_source.id,
 *     isLatest: _var.software_source_module_stream_is_latest,
 *     moduleName: _var.software_source_module_stream_module_name,
 *     moduleNameContains: _var.software_source_module_stream_module_name_contains,
 *     name: _var.software_source_module_stream_name,
 * });
 * ```
 */
export function getSoftwareSourceModuleStreams(args: GetSoftwareSourceModuleStreamsArgs, opts?: pulumi.InvokeOptions): Promise<GetSoftwareSourceModuleStreamsResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:OsManagementHub/getSoftwareSourceModuleStreams:getSoftwareSourceModuleStreams", {
        "filters": args.filters,
        "isLatest": args.isLatest,
        "moduleName": args.moduleName,
        "moduleNameContains": args.moduleNameContains,
        "name": args.name,
        "softwareSourceId": args.softwareSourceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSoftwareSourceModuleStreams.
 */
export interface GetSoftwareSourceModuleStreamsArgs {
    filters?: inputs.OsManagementHub.GetSoftwareSourceModuleStreamsFilter[];
    /**
     * A boolean variable that is used to list only the latest versions of packages, module streams, and stream profiles when set to true. All packages, module streams, and stream profiles are returned when set to false.
     */
    isLatest?: boolean;
    /**
     * The name of a module. This parameter is required if a streamName is specified.
     */
    moduleName?: string;
    /**
     * A filter to return resources that may partially match the module name given.
     */
    moduleNameContains?: string;
    /**
     * The name of the entity to be queried.
     */
    name?: string;
    /**
     * The software source OCID.
     */
    softwareSourceId: string;
}

/**
 * A collection of values returned by getSoftwareSourceModuleStreams.
 */
export interface GetSoftwareSourceModuleStreamsResult {
    readonly filters?: outputs.OsManagementHub.GetSoftwareSourceModuleStreamsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Indicates whether this module stream is the latest.
     */
    readonly isLatest?: boolean;
    /**
     * The name of the module that contains the stream.
     */
    readonly moduleName?: string;
    readonly moduleNameContains?: string;
    /**
     * The list of module_stream_collection.
     */
    readonly moduleStreamCollections: outputs.OsManagementHub.GetSoftwareSourceModuleStreamsModuleStreamCollection[];
    /**
     * The name of the stream.
     */
    readonly name?: string;
    /**
     * The OCID of the software source that provides this module stream.
     */
    readonly softwareSourceId: string;
}
/**
 * This data source provides the list of Software Source Module Streams in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Lists module streams from the specified software source OCID. Filter the list against a variety of
 * criteria including but not limited to its module name and (stream) name.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSoftwareSourceModuleStreams = oci.OsManagementHub.getSoftwareSourceModuleStreams({
 *     softwareSourceId: oci_os_management_hub_software_source.test_software_source.id,
 *     isLatest: _var.software_source_module_stream_is_latest,
 *     moduleName: _var.software_source_module_stream_module_name,
 *     moduleNameContains: _var.software_source_module_stream_module_name_contains,
 *     name: _var.software_source_module_stream_name,
 * });
 * ```
 */
export function getSoftwareSourceModuleStreamsOutput(args: GetSoftwareSourceModuleStreamsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetSoftwareSourceModuleStreamsResult> {
    return pulumi.output(args).apply((a: any) => getSoftwareSourceModuleStreams(a, opts))
}

/**
 * A collection of arguments for invoking getSoftwareSourceModuleStreams.
 */
export interface GetSoftwareSourceModuleStreamsOutputArgs {
    filters?: pulumi.Input<pulumi.Input<inputs.OsManagementHub.GetSoftwareSourceModuleStreamsFilterArgs>[]>;
    /**
     * A boolean variable that is used to list only the latest versions of packages, module streams, and stream profiles when set to true. All packages, module streams, and stream profiles are returned when set to false.
     */
    isLatest?: pulumi.Input<boolean>;
    /**
     * The name of a module. This parameter is required if a streamName is specified.
     */
    moduleName?: pulumi.Input<string>;
    /**
     * A filter to return resources that may partially match the module name given.
     */
    moduleNameContains?: pulumi.Input<string>;
    /**
     * The name of the entity to be queried.
     */
    name?: pulumi.Input<string>;
    /**
     * The software source OCID.
     */
    softwareSourceId: pulumi.Input<string>;
}