// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Software Source resource in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Gets information about the specified software source.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSoftwareSource = oci.OsManagementHub.getSoftwareSource({
 *     softwareSourceId: oci_os_management_hub_software_source.test_software_source.id,
 * });
 * ```
 */
export function getSoftwareSource(args: GetSoftwareSourceArgs, opts?: pulumi.InvokeOptions): Promise<GetSoftwareSourceResult> {

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:OsManagementHub/getSoftwareSource:getSoftwareSource", {
        "softwareSourceId": args.softwareSourceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSoftwareSource.
 */
export interface GetSoftwareSourceArgs {
    /**
     * The software source OCID.
     */
    softwareSourceId: string;
}

/**
 * A collection of values returned by getSoftwareSource.
 */
export interface GetSoftwareSourceResult {
    /**
     * The architecture type supported by the software source.
     */
    readonly archType: string;
    /**
     * Possible availabilities of a software source.
     */
    readonly availability: string;
    /**
     * The yum repository checksum type used by this software source.
     */
    readonly checksumType: string;
    /**
     * The OCID of the tenancy containing the software source.
     */
    readonly compartmentId: string;
    /**
     * Used to apply filters to a VendorSoftwareSource to create/update CustomSoftwareSources.
     */
    readonly customSoftwareSourceFilters: outputs.OsManagementHub.GetSoftwareSourceCustomSoftwareSourceFilter[];
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * Information specified by the user about the software source.
     */
    readonly description: string;
    /**
     * User friendly name.
     */
    readonly displayName: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * Fingerprint of the GPG key for this software source.
     */
    readonly gpgKeyFingerprint: string;
    /**
     * ID of the GPG key for this software source.
     */
    readonly gpgKeyId: string;
    /**
     * URL of the GPG key for this software source.
     */
    readonly gpgKeyUrl: string;
    /**
     * The OCID of the resource that is immutable on creation.
     */
    readonly id: string;
    /**
     * Indicates whether service should automatically update the custom software source for the user.
     */
    readonly isAutomaticallyUpdated: boolean;
    /**
     * The OS family the software source belongs to.
     */
    readonly osFamily: string;
    /**
     * Number of packages.
     */
    readonly packageCount: string;
    /**
     * The Repo ID for the software source.
     */
    readonly repoId: string;
    readonly softwareSourceId: string;
    /**
     * Type of the software source.
     */
    readonly softwareSourceType: string;
    /**
     * The version to assign to this custom software source.
     */
    readonly softwareSourceVersion: string;
    /**
     * The current state of the software source.
     */
    readonly state: string;
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The date and time the software source was created, as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
     */
    readonly timeCreated: string;
    /**
     * URL for the repository.
     */
    readonly url: string;
    /**
     * Name of the vendor providing the software source.
     */
    readonly vendorName: string;
    /**
     * List of vendor software sources.
     */
    readonly vendorSoftwareSources: outputs.OsManagementHub.GetSoftwareSourceVendorSoftwareSource[];
}
/**
 * This data source provides details about a specific Software Source resource in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Gets information about the specified software source.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSoftwareSource = oci.OsManagementHub.getSoftwareSource({
 *     softwareSourceId: oci_os_management_hub_software_source.test_software_source.id,
 * });
 * ```
 */
export function getSoftwareSourceOutput(args: GetSoftwareSourceOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetSoftwareSourceResult> {
    return pulumi.output(args).apply((a: any) => getSoftwareSource(a, opts))
}

/**
 * A collection of arguments for invoking getSoftwareSource.
 */
export interface GetSoftwareSourceOutputArgs {
    /**
     * The software source OCID.
     */
    softwareSourceId: pulumi.Input<string>;
}