// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Software Source Module Stream resource in Oracle Cloud Infrastructure OS Management service.
 *
 * Retrieve a detailed description of a module stream from a software source.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSoftwareSourceModuleStream = oci.OsManagement.getSoftwareSourceModuleStream({
 *     moduleName: _var.software_source_module_stream_module_name,
 *     softwareSourceId: _var.software_source.id,
 *     streamName: _var.software_source_module_stream_name,
 * });
 * ```
 */
export function getSoftwareSourceModuleStream(args: GetSoftwareSourceModuleStreamArgs, opts?: pulumi.InvokeOptions): Promise<GetSoftwareSourceModuleStreamResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:OsManagement/getSoftwareSourceModuleStream:getSoftwareSourceModuleStream", {
        "moduleName": args.moduleName,
        "softwareSourceId": args.softwareSourceId,
        "streamName": args.streamName,
    }, opts);
}

/**
 * A collection of arguments for invoking getSoftwareSourceModuleStream.
 */
export interface GetSoftwareSourceModuleStreamArgs {
    /**
     * The name of the module
     */
    moduleName: string;
    /**
     * The OCID of the software source.
     */
    softwareSourceId: string;
    /**
     * The name of the stream of the containing module
     */
    streamName: string;
}

/**
 * A collection of values returned by getSoftwareSourceModuleStream.
 */
export interface GetSoftwareSourceModuleStreamResult {
    /**
     * The architecture for which the packages in this module stream were built
     */
    readonly architecture: string;
    /**
     * A description of the contents of the module stream
     */
    readonly description: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Indicates if this stream is the default for its module.
     */
    readonly isDefault: boolean;
    /**
     * The name of the module that contains the stream
     */
    readonly moduleName: string;
    /**
     * A list of packages that are contained by the stream.  Each element in the list is the name of a package.  The name is suitable to use as an argument to other OS Management APIs that interact directly with packages.
     */
    readonly packages: string[];
    /**
     * A list of profiles that are part of the stream.  Each element in the list is the name of a profile.  The name is suitable to use as an argument to other OS Management APIs that interact directly with module stream profiles.  However, it is not URL encoded.
     */
    readonly profiles: string[];
    /**
     * The OCID of the software source that provides this module stream.
     */
    readonly softwareSourceId: string;
    /**
     * The name of the stream
     */
    readonly streamName: string;
}

export function getSoftwareSourceModuleStreamOutput(args: GetSoftwareSourceModuleStreamOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetSoftwareSourceModuleStreamResult> {
    return pulumi.output(args).apply(a => getSoftwareSourceModuleStream(a, opts))
}

/**
 * A collection of arguments for invoking getSoftwareSourceModuleStream.
 */
export interface GetSoftwareSourceModuleStreamOutputArgs {
    /**
     * The name of the module
     */
    moduleName: pulumi.Input<string>;
    /**
     * The OCID of the software source.
     */
    softwareSourceId: pulumi.Input<string>;
    /**
     * The name of the stream of the containing module
     */
    streamName: pulumi.Input<string>;
}