// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Associations in Oracle Cloud Infrastructure Certificates Management service.
 *
 * Lists all associations that match the query parameters.
 * Optionally, you can use the parameter `FilterByAssociationIdQueryParam` to limit the result set to a single item that matches the specified association.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAssociations = oci.CertificatesManagement.getAssociations({
 *     associatedResourceId: oci_certificates_management_associated_resource.test_associated_resource.id,
 *     associationId: oci_certificates_management_association.test_association.id,
 *     associationType: _var.association_association_type,
 *     certificatesResourceId: oci_certificates_management_certificates_resource.test_certificates_resource.id,
 *     compartmentId: _var.compartment_id,
 *     name: _var.association_name,
 * });
 * ```
 */
export function getAssociations(args?: GetAssociationsArgs, opts?: pulumi.InvokeOptions): Promise<GetAssociationsResult> {
    args = args || {};
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:CertificatesManagement/getAssociations:getAssociations", {
        "associatedResourceId": args.associatedResourceId,
        "associationId": args.associationId,
        "associationType": args.associationType,
        "certificatesResourceId": args.certificatesResourceId,
        "compartmentId": args.compartmentId,
        "filters": args.filters,
        "name": args.name,
    }, opts);
}

/**
 * A collection of arguments for invoking getAssociations.
 */
export interface GetAssociationsArgs {
    /**
     * A filter that returns only resources that match the given OCID of an associated Oracle Cloud Infrastructure resource.
     */
    associatedResourceId?: string;
    /**
     * The OCID of the association. If the parameter is set to null, the service lists all associations.
     */
    associationId?: string;
    /**
     * Type of associations to list. If the parameter is set to null, the service lists all types of associations.
     */
    associationType?: string;
    /**
     * A filter that returns only resources that match the given OCID of a certificate-related resource.
     */
    certificatesResourceId?: string;
    /**
     * A filter that returns only resources that match the given compartment OCID.
     */
    compartmentId?: string;
    filters?: inputs.CertificatesManagement.GetAssociationsFilter[];
    /**
     * A filter that returns only resources that match the specified name.
     */
    name?: string;
}

/**
 * A collection of values returned by getAssociations.
 */
export interface GetAssociationsResult {
    /**
     * The OCID of the associated resource.
     */
    readonly associatedResourceId?: string;
    /**
     * The list of association_collection.
     */
    readonly associationCollections: outputs.CertificatesManagement.GetAssociationsAssociationCollection[];
    readonly associationId?: string;
    /**
     * Type of the association.
     */
    readonly associationType?: string;
    /**
     * The OCID of the certificate-related resource associated with another Oracle Cloud Infrastructure resource.
     */
    readonly certificatesResourceId?: string;
    /**
     * The compartment OCID of the association, which is strongly tied to the compartment OCID of the certificate-related resource.
     */
    readonly compartmentId?: string;
    readonly filters?: outputs.CertificatesManagement.GetAssociationsFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * A user-friendly name generated by the service for the association, expressed in a format that follows the pattern: [certificatesResourceEntityType]-[associatedResourceEntityType]-UUID.
     */
    readonly name?: string;
}

export function getAssociationsOutput(args?: GetAssociationsOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetAssociationsResult> {
    return pulumi.output(args).apply(a => getAssociations(a, opts))
}

/**
 * A collection of arguments for invoking getAssociations.
 */
export interface GetAssociationsOutputArgs {
    /**
     * A filter that returns only resources that match the given OCID of an associated Oracle Cloud Infrastructure resource.
     */
    associatedResourceId?: pulumi.Input<string>;
    /**
     * The OCID of the association. If the parameter is set to null, the service lists all associations.
     */
    associationId?: pulumi.Input<string>;
    /**
     * Type of associations to list. If the parameter is set to null, the service lists all types of associations.
     */
    associationType?: pulumi.Input<string>;
    /**
     * A filter that returns only resources that match the given OCID of a certificate-related resource.
     */
    certificatesResourceId?: pulumi.Input<string>;
    /**
     * A filter that returns only resources that match the given compartment OCID.
     */
    compartmentId?: pulumi.Input<string>;
    filters?: pulumi.Input<pulumi.Input<inputs.CertificatesManagement.GetAssociationsFilterArgs>[]>;
    /**
     * A filter that returns only resources that match the specified name.
     */
    name?: pulumi.Input<string>;
}