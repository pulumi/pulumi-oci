// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Certificate resource in Oracle Cloud Infrastructure Certificates Management service.
 *
 * Creates a new certificate according to the details of the request.
 *
 * ## Import
 *
 * Certificates can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:CertificatesManagement/certificate:Certificate test_certificate "id"
 * ```
 */
export class Certificate extends pulumi.CustomResource {
    /**
     * Get an existing Certificate resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: CertificateState, opts?: pulumi.CustomResourceOptions): Certificate {
        return new Certificate(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:CertificatesManagement/certificate:Certificate';

    /**
     * Returns true if the given object is an instance of Certificate.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Certificate {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Certificate.__pulumiType;
    }

    /**
     * (Updatable) The details of the contents of the certificate and certificate metadata.
     */
    public readonly certificateConfig!: pulumi.Output<outputs.CertificatesManagement.CertificateCertificateConfig>;
    /**
     * The name of the profile used to create the certificate, which depends on the type of certificate you need.
     */
    public /*out*/ readonly certificateProfileType!: pulumi.Output<string>;
    /**
     * The details of the certificate revocation list (CRL).
     */
    public /*out*/ readonly certificateRevocationListDetails!: pulumi.Output<outputs.CertificatesManagement.CertificateCertificateRevocationListDetail[]>;
    /**
     * (Updatable) An optional list of rules that control how the certificate is used and managed.
     */
    public readonly certificateRules!: pulumi.Output<outputs.CertificatesManagement.CertificateCertificateRule[] | undefined>;
    /**
     * (Updatable) The OCID of the compartment where you want to create the certificate.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The origin of the certificate.
     */
    public /*out*/ readonly configType!: pulumi.Output<string>;
    /**
     * The details of the certificate version. This object does not contain the certificate contents.
     */
    public /*out*/ readonly currentVersions!: pulumi.Output<outputs.CertificatesManagement.CertificateCurrentVersion[]>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) A brief description of the certificate. Avoid entering confidential information.
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * The OCID of the certificate authority (CA) that issued the certificate.
     */
    public /*out*/ readonly issuerCertificateAuthorityId!: pulumi.Output<string>;
    /**
     * The algorithm used to create key pairs.
     */
    public /*out*/ readonly keyAlgorithm!: pulumi.Output<string>;
    /**
     * Additional information about the current lifecycle state of the certificate.
     */
    public /*out*/ readonly lifecycleDetails!: pulumi.Output<string>;
    /**
     * A user-friendly name for the certificate. Names are unique within a compartment. Avoid entering confidential information. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly name!: pulumi.Output<string>;
    /**
     * The algorithm used to sign the public key certificate.
     */
    public /*out*/ readonly signatureAlgorithm!: pulumi.Output<string>;
    /**
     * The current lifecycle state of the certificate.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
     */
    public /*out*/ readonly subjects!: pulumi.Output<outputs.CertificatesManagement.CertificateSubject[]>;
    /**
     * A property indicating when the certificate was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * An optional property indicating when to delete the certificate version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     */
    public /*out*/ readonly timeOfDeletion!: pulumi.Output<string>;

    /**
     * Create a Certificate resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: CertificateArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: CertificateArgs | CertificateState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as CertificateState | undefined;
            resourceInputs["certificateConfig"] = state ? state.certificateConfig : undefined;
            resourceInputs["certificateProfileType"] = state ? state.certificateProfileType : undefined;
            resourceInputs["certificateRevocationListDetails"] = state ? state.certificateRevocationListDetails : undefined;
            resourceInputs["certificateRules"] = state ? state.certificateRules : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["configType"] = state ? state.configType : undefined;
            resourceInputs["currentVersions"] = state ? state.currentVersions : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["description"] = state ? state.description : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["issuerCertificateAuthorityId"] = state ? state.issuerCertificateAuthorityId : undefined;
            resourceInputs["keyAlgorithm"] = state ? state.keyAlgorithm : undefined;
            resourceInputs["lifecycleDetails"] = state ? state.lifecycleDetails : undefined;
            resourceInputs["name"] = state ? state.name : undefined;
            resourceInputs["signatureAlgorithm"] = state ? state.signatureAlgorithm : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["subjects"] = state ? state.subjects : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeOfDeletion"] = state ? state.timeOfDeletion : undefined;
        } else {
            const args = argsOrState as CertificateArgs | undefined;
            if ((!args || args.certificateConfig === undefined) && !opts.urn) {
                throw new Error("Missing required property 'certificateConfig'");
            }
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            resourceInputs["certificateConfig"] = args ? args.certificateConfig : undefined;
            resourceInputs["certificateRules"] = args ? args.certificateRules : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["description"] = args ? args.description : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["name"] = args ? args.name : undefined;
            resourceInputs["certificateProfileType"] = undefined /*out*/;
            resourceInputs["certificateRevocationListDetails"] = undefined /*out*/;
            resourceInputs["configType"] = undefined /*out*/;
            resourceInputs["currentVersions"] = undefined /*out*/;
            resourceInputs["issuerCertificateAuthorityId"] = undefined /*out*/;
            resourceInputs["keyAlgorithm"] = undefined /*out*/;
            resourceInputs["lifecycleDetails"] = undefined /*out*/;
            resourceInputs["signatureAlgorithm"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["subjects"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeOfDeletion"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(Certificate.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Certificate resources.
 */
export interface CertificateState {
    /**
     * (Updatable) The details of the contents of the certificate and certificate metadata.
     */
    certificateConfig?: pulumi.Input<inputs.CertificatesManagement.CertificateCertificateConfig>;
    /**
     * The name of the profile used to create the certificate, which depends on the type of certificate you need.
     */
    certificateProfileType?: pulumi.Input<string>;
    /**
     * The details of the certificate revocation list (CRL).
     */
    certificateRevocationListDetails?: pulumi.Input<pulumi.Input<inputs.CertificatesManagement.CertificateCertificateRevocationListDetail>[]>;
    /**
     * (Updatable) An optional list of rules that control how the certificate is used and managed.
     */
    certificateRules?: pulumi.Input<pulumi.Input<inputs.CertificatesManagement.CertificateCertificateRule>[]>;
    /**
     * (Updatable) The OCID of the compartment where you want to create the certificate.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The origin of the certificate.
     */
    configType?: pulumi.Input<string>;
    /**
     * The details of the certificate version. This object does not contain the certificate contents.
     */
    currentVersions?: pulumi.Input<pulumi.Input<inputs.CertificatesManagement.CertificateCurrentVersion>[]>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A brief description of the certificate. Avoid entering confidential information.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * The OCID of the certificate authority (CA) that issued the certificate.
     */
    issuerCertificateAuthorityId?: pulumi.Input<string>;
    /**
     * The algorithm used to create key pairs.
     */
    keyAlgorithm?: pulumi.Input<string>;
    /**
     * Additional information about the current lifecycle state of the certificate.
     */
    lifecycleDetails?: pulumi.Input<string>;
    /**
     * A user-friendly name for the certificate. Names are unique within a compartment. Avoid entering confidential information. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    name?: pulumi.Input<string>;
    /**
     * The algorithm used to sign the public key certificate.
     */
    signatureAlgorithm?: pulumi.Input<string>;
    /**
     * The current lifecycle state of the certificate.
     */
    state?: pulumi.Input<string>;
    /**
     * The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
     */
    subjects?: pulumi.Input<pulumi.Input<inputs.CertificatesManagement.CertificateSubject>[]>;
    /**
     * A property indicating when the certificate was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * An optional property indicating when to delete the certificate version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
     */
    timeOfDeletion?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Certificate resource.
 */
export interface CertificateArgs {
    /**
     * (Updatable) The details of the contents of the certificate and certificate metadata.
     */
    certificateConfig: pulumi.Input<inputs.CertificatesManagement.CertificateCertificateConfig>;
    /**
     * (Updatable) An optional list of rules that control how the certificate is used and managed.
     */
    certificateRules?: pulumi.Input<pulumi.Input<inputs.CertificatesManagement.CertificateCertificateRule>[]>;
    /**
     * (Updatable) The OCID of the compartment where you want to create the certificate.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A brief description of the certificate. Avoid entering confidential information.
     */
    description?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * A user-friendly name for the certificate. Names are unique within a compartment. Avoid entering confidential information. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    name?: pulumi.Input<string>;
}
