// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Email Domain resource in Oracle Cloud Infrastructure Email service.
 *
 * Retrieves the specified email domain.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testEmailDomain = oci.Email.getEmailDomain({
 *     emailDomainId: testEmailDomainOciEmailEmailDomain.id,
 * });
 * ```
 */
export function getEmailDomain(args: GetEmailDomainArgs, opts?: pulumi.InvokeOptions): Promise<GetEmailDomainResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:Email/getEmailDomain:getEmailDomain", {
        "emailDomainId": args.emailDomainId,
    }, opts);
}

/**
 * A collection of arguments for invoking getEmailDomain.
 */
export interface GetEmailDomainArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this email domain.
     */
    emailDomainId: string;
}

/**
 * A collection of values returned by getEmailDomain.
 */
export interface GetEmailDomainResult {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DKIM key that will be used to sign mail sent from this email domain.
     */
    readonly activeDkimId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains this email domain.
     */
    readonly compartmentId: string;
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * The description of an email domain.
     */
    readonly description: string;
    /**
     * Id for Domain in Domain Management (under governance) if DOMAINID verification method used.
     */
    readonly domainVerificationId: string;
    /**
     * The current domain verification status.
     */
    readonly domainVerificationStatus: string;
    readonly emailDomainId: string;
    /**
     * Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email domain.
     */
    readonly id: string;
    /**
     * Value of the SPF field. For more information about SPF, please see [SPF Authentication](https://docs.cloud.oracle.com/iaas/Content/Email/Concepts/overview.htm#components).
     */
    readonly isSpf: boolean;
    /**
     * The name of the email domain in the Internet Domain Name System (DNS).  Example: `mydomain.example.com`
     */
    readonly name: string;
    /**
     * The current state of the email domain.
     */
    readonly state: string;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    readonly systemTags: {[key: string]: string};
    /**
     * The time the email domain was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, "YYYY-MM-ddThh:mmZ".  Example: `2021-02-12T22:47:12.613Z`
     */
    readonly timeCreated: string;
}
/**
 * This data source provides details about a specific Email Domain resource in Oracle Cloud Infrastructure Email service.
 *
 * Retrieves the specified email domain.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testEmailDomain = oci.Email.getEmailDomain({
 *     emailDomainId: testEmailDomainOciEmailEmailDomain.id,
 * });
 * ```
 */
export function getEmailDomainOutput(args: GetEmailDomainOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetEmailDomainResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:Email/getEmailDomain:getEmailDomain", {
        "emailDomainId": args.emailDomainId,
    }, opts);
}

/**
 * A collection of arguments for invoking getEmailDomain.
 */
export interface GetEmailDomainOutputArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this email domain.
     */
    emailDomainId: pulumi.Input<string>;
}
