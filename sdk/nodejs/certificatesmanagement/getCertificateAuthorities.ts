// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Certificate Authorities in Oracle Cloud Infrastructure Certificates Management service.
 *
 * Lists all certificate authorities (CAs) in the specified compartment.
 * Optionally, you can use the parameter `FilterByCertificateAuthorityIdQueryParam` to limit the results to a single item that matches the specified CA.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testCertificateAuthorities = oci.CertificatesManagement.getCertificateAuthorities({
 *     certificateAuthorityId: oci_certificates_management_certificate_authority.test_certificate_authority.id,
 *     compartmentId: _var.compartment_id,
 *     issuerCertificateAuthorityId: oci_certificates_management_certificate_authority.test_certificate_authority.id,
 *     name: _var.certificate_authority_name,
 *     state: _var.certificate_authority_state,
 * });
 * ```
 */
export function getCertificateAuthorities(args?: GetCertificateAuthoritiesArgs, opts?: pulumi.InvokeOptions): Promise<GetCertificateAuthoritiesResult> {
    args = args || {};
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:CertificatesManagement/getCertificateAuthorities:getCertificateAuthorities", {
        "certificateAuthorityId": args.certificateAuthorityId,
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "issuerCertificateAuthorityId": args.issuerCertificateAuthorityId,
        "name": args.name,
        "state": args.state,
    }, opts);
}

/**
 * A collection of arguments for invoking getCertificateAuthorities.
 */
export interface GetCertificateAuthoritiesArgs {
    /**
     * The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
     */
    certificateAuthorityId?: string;
    /**
     * A filter that returns only resources that match the given compartment OCID.
     */
    compartmentId?: string;
    filters?: inputs.CertificatesManagement.GetCertificateAuthoritiesFilter[];
    /**
     * The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
     */
    issuerCertificateAuthorityId?: string;
    /**
     * A filter that returns only resources that match the specified name.
     */
    name?: string;
    /**
     * A filter that returns only resources that match the given lifecycle state. The state value is case-insensitive.
     */
    state?: string;
}

/**
 * A collection of values returned by getCertificateAuthorities.
 */
export interface GetCertificateAuthoritiesResult {
    /**
     * The list of certificate_authority_collection.
     */
    readonly certificateAuthorityCollections: outputs.CertificatesManagement.GetCertificateAuthoritiesCertificateAuthorityCollection[];
    /**
     * The OCID of the CA.
     */
    readonly certificateAuthorityId?: string;
    /**
     * The OCID of the compartment under which the CA is created.
     */
    readonly compartmentId?: string;
    readonly filters?: outputs.CertificatesManagement.GetCertificateAuthoritiesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The OCID of the parent CA that issued this CA. If this is the root CA, then this value is null.
     */
    readonly issuerCertificateAuthorityId?: string;
    /**
     * A user-friendly name for the CA. Names are unique within a compartment. Avoid entering confidential information. Valid characters include uppercase or lowercase letters, numbers, hyphens, underscores, and periods.
     */
    readonly name?: string;
    /**
     * The current lifecycle state of the certificate authority.
     */
    readonly state?: string;
}

export function getCertificateAuthoritiesOutput(args?: GetCertificateAuthoritiesOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetCertificateAuthoritiesResult> {
    return pulumi.output(args).apply(a => getCertificateAuthorities(a, opts))
}

/**
 * A collection of arguments for invoking getCertificateAuthorities.
 */
export interface GetCertificateAuthoritiesOutputArgs {
    /**
     * The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
     */
    certificateAuthorityId?: pulumi.Input<string>;
    /**
     * A filter that returns only resources that match the given compartment OCID.
     */
    compartmentId?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.CertificatesManagement.GetCertificateAuthoritiesFilterArgs>[]>;
    /**
     * The OCID of the certificate authority (CA). If the parameter is set to null, the service lists all CAs.
     */
    issuerCertificateAuthorityId?: pulumi.Input<string>;
    /**
     * A filter that returns only resources that match the specified name.
     */
    name?: pulumi.Input<string>;
    /**
     * A filter that returns only resources that match the given lifecycle state. The state value is case-insensitive.
     */
    state?: pulumi.Input<string>;
}