// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific License Record resource in Oracle Cloud Infrastructure License Manager service.
 *
 * Retrieves license record details by the license record ID in a given compartment.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testLicenseRecord = oci.LicenseManager.getLicenseRecord({
 *     licenseRecordId: oci_license_manager_license_record.test_license_record.id,
 * });
 * ```
 */
export function getLicenseRecord(args: GetLicenseRecordArgs, opts?: pulumi.InvokeOptions): Promise<GetLicenseRecordResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:LicenseManager/getLicenseRecord:getLicenseRecord", {
        "licenseRecordId": args.licenseRecordId,
    }, opts);
}

/**
 * A collection of arguments for invoking getLicenseRecord.
 */
export interface GetLicenseRecordArgs {
    /**
     * Unique license record identifier.
     */
    licenseRecordId: string;
}

/**
 * A collection of values returned by getLicenseRecord.
 */
export interface GetLicenseRecordResult {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) where the license record is created.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: any};
    /**
     * The license record display name. Avoid entering confidential information.
     */
    readonly displayName: string;
    /**
     * The license record end date in [RFC 3339](https://tools.ietf.org/html/rfc3339) date format. Example: `2018-09-12`
     */
    readonly expirationDate: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: any};
    /**
     * The license record [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    readonly id: string;
    /**
     * Specifies if the license record term is perpertual.
     */
    readonly isPerpetual: boolean;
    /**
     * Specifies if the license count is unlimited.
     */
    readonly isUnlimited: boolean;
    /**
     * The number of license units added by the user for the given license record. Default 1
     */
    readonly licenseCount: number;
    readonly licenseRecordId: string;
    /**
     * The product license unit.
     */
    readonly licenseUnit: string;
    /**
     * The license record product ID.
     */
    readonly productId: string;
    /**
     * The product license name with which the license record is associated.
     */
    readonly productLicense: string;
    /**
     * The product license [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) with which the license record is associated.
     */
    readonly productLicenseId: string;
    /**
     * The current license record state.
     */
    readonly state: string;
    /**
     * The license record support end date in [RFC 3339](https://tools.ietf.org/html/rfc3339) date format. Example: `2018-09-12`
     */
    readonly supportEndDate: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: any};
    /**
     * The time the license record was created. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
     */
    readonly timeCreated: string;
    /**
     * The time the license record was updated. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
     */
    readonly timeUpdated: string;
}

export function getLicenseRecordOutput(args: GetLicenseRecordOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetLicenseRecordResult> {
    return pulumi.output(args).apply(a => getLicenseRecord(a, opts))
}

/**
 * A collection of arguments for invoking getLicenseRecord.
 */
export interface GetLicenseRecordOutputArgs {
    /**
     * Unique license record identifier.
     */
    licenseRecordId: pulumi.Input<string>;
}