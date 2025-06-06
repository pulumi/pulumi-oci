// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Certificate Authority resource in Oracle Cloud Infrastructure Certificates Management service.
 *
 * Gets details about the specified certificate authority (CA).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCertificateAuthority = oci.CertificatesManagement.getCertificateAuthority({
 *     certificateAuthorityId: testCertificateAuthorityOciCertificatesManagementCertificateAuthority.id,
 * });
 * ```
 */
export function getCertificateAuthority(args: GetCertificateAuthorityArgs, opts?: pulumi.InvokeOptions): Promise<GetCertificateAuthorityResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:CertificatesManagement/getCertificateAuthority:getCertificateAuthority", {
        "certificateAuthorityId": args.certificateAuthorityId,
    }, opts);
}

/**
 * A collection of arguments for invoking getCertificateAuthority.
 */
export interface GetCertificateAuthorityArgs {
    /**
     * The OCID of the certificate authority (CA).
     */
    certificateAuthorityId: string;
}

/**
 * A collection of values returned by getCertificateAuthority.
 */
export interface GetCertificateAuthorityResult {
    readonly certificateAuthorityConfigs: outputs.CertificatesManagement.GetCertificateAuthorityCertificateAuthorityConfig[];
    /**
     * The OCID of the CA.
     */
    readonly certificateAuthorityId: string;
    /**
     * An optional list of rules that control how the CA is used and managed.
     */
    readonly certificateAuthorityRules: outputs.CertificatesManagement.GetCertificateAuthorityCertificateAuthorityRule[];
    /**
     * The details of the certificate revocation list (CRL).
     */
    readonly certificateRevocationListDetails: outputs.CertificatesManagement.GetCertificateAuthorityCertificateRevocationListDetail[];
    /**
     * The OCID of the compartment under which the CA is created.
     */
    readonly compartmentId: string;
    /**
     * The origin of the CA.
     */
    readonly configType: string;
    /**
     * The metadata details of the certificate authority (CA) version. This summary object does not contain the CA contents.
     */
    readonly currentVersions: outputs.CertificatesManagement.GetCertificateAuthorityCurrentVersion[];
    /**
     * Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
     */
    readonly definedTags: {[key: string]: string};
    /**
     * A brief description of the CA.
     */
    readonly description: string;
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    readonly freeformTags: {[key: string]: string};
    /**
     * The OCID of the CA.
     */
    readonly id: string;
    /**
     * The OCID of the parent CA that issued this CA. If this is the root CA, then this value is null.
     */
    readonly issuerCertificateAuthorityId: string;
    /**
     * The OCID of the Oracle Cloud Infrastructure Vault key used to encrypt the CA.
     */
    readonly kmsKeyId: string;
    /**
     * Additional information about the current CA lifecycle state.
     */
    readonly lifecycleDetails: string;
    /**
     * A user-friendly name for the CA. Names are unique within a compartment. Avoid entering confidential information. Valid characters include uppercase or lowercase letters, numbers, hyphens, underscores, and periods.
     */
    readonly name: string;
    /**
     * The algorithm used to sign public key certificates that the CA issues.
     */
    readonly signingAlgorithm: string;
    /**
     * The current lifecycle state of the certificate authority.
     */
    readonly state: string;
    /**
     * The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
     */
    readonly subjects: outputs.CertificatesManagement.GetCertificateAuthoritySubject[];
    /**
     * A property indicating when the CA was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     */
    readonly timeCreated: string;
    /**
     * An optional property indicating when to delete the CA version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     */
    readonly timeOfDeletion: string;
}
/**
 * This data source provides details about a specific Certificate Authority resource in Oracle Cloud Infrastructure Certificates Management service.
 *
 * Gets details about the specified certificate authority (CA).
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCertificateAuthority = oci.CertificatesManagement.getCertificateAuthority({
 *     certificateAuthorityId: testCertificateAuthorityOciCertificatesManagementCertificateAuthority.id,
 * });
 * ```
 */
export function getCertificateAuthorityOutput(args: GetCertificateAuthorityOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetCertificateAuthorityResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:CertificatesManagement/getCertificateAuthority:getCertificateAuthority", {
        "certificateAuthorityId": args.certificateAuthorityId,
    }, opts);
}

/**
 * A collection of arguments for invoking getCertificateAuthority.
 */
export interface GetCertificateAuthorityOutputArgs {
    /**
     * The OCID of the certificate authority (CA).
     */
    certificateAuthorityId: pulumi.Input<string>;
}
