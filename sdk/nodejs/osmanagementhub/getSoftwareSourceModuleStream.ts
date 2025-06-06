// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Software Source Module Stream resource in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Returns information about the specified module stream in a software source.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSoftwareSourceModuleStream = oci.OsManagementHub.getSoftwareSourceModuleStream({
 *     moduleName: softwareSourceModuleStreamModuleName,
 *     softwareSourceId: testSoftwareSource.id,
 *     streamName: testStream.name,
 * });
 * ```
 */
export function getSoftwareSourceModuleStream(args: GetSoftwareSourceModuleStreamArgs, opts?: pulumi.InvokeOptions): Promise<GetSoftwareSourceModuleStreamResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:OsManagementHub/getSoftwareSourceModuleStream:getSoftwareSourceModuleStream", {
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
     * The name of the module.
     */
    moduleName: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
     */
    softwareSourceId: string;
    /**
     * The name of the stream of the containing module.
     */
    streamName: string;
}

/**
 * A collection of values returned by getSoftwareSourceModuleStream.
 */
export interface GetSoftwareSourceModuleStreamResult {
    /**
     * The architecture for which the packages in this module stream were built.
     */
    readonly archType: string;
    /**
     * A description of the contents of the module stream.
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
     * Indicates whether this module stream is the latest.
     */
    readonly isLatest: boolean;
    /**
     * The name of the module that contains the stream.
     */
    readonly moduleName: string;
    /**
     * The name of the stream.
     */
    readonly name: string;
    /**
     * A list of packages that are contained by the stream.  Each element in the list is the name of a package.  The name is suitable to use as an argument to other OS Management Hub APIs that interact directly with packages.
     */
    readonly packages: string[];
    /**
     * A list of profiles that are part of the stream.  Each element in the list is the name of a profile.  The name is suitable to use as an argument to other OS Management Hub APIs that interact directly with module stream profiles.  However, it is not URL encoded.
     */
    readonly profiles: string[];
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source that provides this module stream.
     */
    readonly softwareSourceId: string;
    readonly streamName: string;
}
/**
 * This data source provides details about a specific Software Source Module Stream resource in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Returns information about the specified module stream in a software source.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSoftwareSourceModuleStream = oci.OsManagementHub.getSoftwareSourceModuleStream({
 *     moduleName: softwareSourceModuleStreamModuleName,
 *     softwareSourceId: testSoftwareSource.id,
 *     streamName: testStream.name,
 * });
 * ```
 */
export function getSoftwareSourceModuleStreamOutput(args: GetSoftwareSourceModuleStreamOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetSoftwareSourceModuleStreamResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:OsManagementHub/getSoftwareSourceModuleStream:getSoftwareSourceModuleStream", {
        "moduleName": args.moduleName,
        "softwareSourceId": args.softwareSourceId,
        "streamName": args.streamName,
    }, opts);
}

/**
 * A collection of arguments for invoking getSoftwareSourceModuleStream.
 */
export interface GetSoftwareSourceModuleStreamOutputArgs {
    /**
     * The name of the module.
     */
    moduleName: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
     */
    softwareSourceId: pulumi.Input<string>;
    /**
     * The name of the stream of the containing module.
     */
    streamName: pulumi.Input<string>;
}
