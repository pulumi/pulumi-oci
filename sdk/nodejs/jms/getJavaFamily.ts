// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Java Family resource in Oracle Cloud Infrastructure Jms service.
 *
 * Returns metadata associated with a specific Java release family.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testJavaFamily = oci.Jms.getJavaFamily({
 *     familyVersion: javaFamilyFamilyVersion,
 * });
 * ```
 */
export function getJavaFamily(args: GetJavaFamilyArgs, opts?: pulumi.InvokeOptions): Promise<GetJavaFamilyResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Jms/getJavaFamily:getJavaFamily", {
        "familyVersion": args.familyVersion,
    }, opts);
}

/**
 * A collection of arguments for invoking getJavaFamily.
 */
export interface GetJavaFamilyArgs {
    /**
     * Unique Java family version identifier.
     */
    familyVersion: string;
}

/**
 * A collection of values returned by getJavaFamily.
 */
export interface GetJavaFamilyResult {
    /**
     * The display name of the release family.
     */
    readonly displayName: string;
    /**
     * Link to access the documentation for the release.
     */
    readonly docUrl: string;
    /**
     * The End of Support Life (EOSL) date of the Java release family (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     */
    readonly endOfSupportLifeDate: string;
    /**
     * The Java release family identifier.
     */
    readonly familyVersion: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Whether or not this Java release family is under active support. Refer [Java Support Roadmap](https://www.oracle.com/java/technologies/java-se-support-roadmap.html) for more details.
     */
    readonly isSupportedVersion: boolean;
    /**
     * List of artifacts for the latest Java release version in this family. The script URLs in the response can be used from a command line, or in scripts and dockerfiles to always get the artifacts corresponding to the latest update release version.
     */
    readonly latestReleaseArtifacts: outputs.Jms.GetJavaFamilyLatestReleaseArtifact[];
    /**
     * Latest Java release version in the family.
     */
    readonly latestReleaseVersion: string;
    /**
     * The date on which the Java release family was first made available (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
     */
    readonly releaseDate: string;
    /**
     * This indicates the support category for the Java release family.
     */
    readonly supportType: string;
}
/**
 * This data source provides details about a specific Java Family resource in Oracle Cloud Infrastructure Jms service.
 *
 * Returns metadata associated with a specific Java release family.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testJavaFamily = oci.Jms.getJavaFamily({
 *     familyVersion: javaFamilyFamilyVersion,
 * });
 * ```
 */
export function getJavaFamilyOutput(args: GetJavaFamilyOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetJavaFamilyResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Jms/getJavaFamily:getJavaFamily", {
        "familyVersion": args.familyVersion,
    }, opts);
}

/**
 * A collection of arguments for invoking getJavaFamily.
 */
export interface GetJavaFamilyOutputArgs {
    /**
     * Unique Java family version identifier.
     */
    familyVersion: pulumi.Input<string>;
}
