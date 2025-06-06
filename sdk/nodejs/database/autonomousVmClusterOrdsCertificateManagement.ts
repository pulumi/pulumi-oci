// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Autonomous Vm Cluster Ords Certificate Management resource in Oracle Cloud Infrastructure Database service.
 *
 * Rotates the Oracle REST Data Services (ORDS) certificates for Autonomous Exadata VM cluster.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAutonomousVmClusterOrdsCertificateManagement = new oci.database.AutonomousVmClusterOrdsCertificateManagement("test_autonomous_vm_cluster_ords_certificate_management", {
 *     autonomousVmClusterId: testAutonomousVmCluster.id,
 *     certificateGenerationType: autonomousVmClusterOrdsCertificateManagementCertificateGenerationType,
 *     caBundleId: testCaBundle.id,
 *     certificateAuthorityId: testCertificateAuthority.id,
 *     certificateId: testCertificate.id,
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class AutonomousVmClusterOrdsCertificateManagement extends pulumi.CustomResource {
    /**
     * Get an existing AutonomousVmClusterOrdsCertificateManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AutonomousVmClusterOrdsCertificateManagementState, opts?: pulumi.CustomResourceOptions): AutonomousVmClusterOrdsCertificateManagement {
        return new AutonomousVmClusterOrdsCertificateManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Database/autonomousVmClusterOrdsCertificateManagement:AutonomousVmClusterOrdsCertificateManagement';

    /**
     * Returns true if the given object is an instance of AutonomousVmClusterOrdsCertificateManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AutonomousVmClusterOrdsCertificateManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AutonomousVmClusterOrdsCertificateManagement.__pulumiType;
    }

    /**
     * The autonomous VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    public readonly autonomousVmClusterId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the certificate bundle.
     */
    public readonly caBundleId!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the certificate authority.
     */
    public readonly certificateAuthorityId!: pulumi.Output<string>;
    /**
     * Specify SYSTEM for using Oracle managed certificates. Specify BYOC when you want to bring your own certificate.
     */
    public readonly certificateGenerationType!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the certificate to use. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly certificateId!: pulumi.Output<string>;

    /**
     * Create a AutonomousVmClusterOrdsCertificateManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: AutonomousVmClusterOrdsCertificateManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AutonomousVmClusterOrdsCertificateManagementArgs | AutonomousVmClusterOrdsCertificateManagementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AutonomousVmClusterOrdsCertificateManagementState | undefined;
            resourceInputs["autonomousVmClusterId"] = state ? state.autonomousVmClusterId : undefined;
            resourceInputs["caBundleId"] = state ? state.caBundleId : undefined;
            resourceInputs["certificateAuthorityId"] = state ? state.certificateAuthorityId : undefined;
            resourceInputs["certificateGenerationType"] = state ? state.certificateGenerationType : undefined;
            resourceInputs["certificateId"] = state ? state.certificateId : undefined;
        } else {
            const args = argsOrState as AutonomousVmClusterOrdsCertificateManagementArgs | undefined;
            if ((!args || args.autonomousVmClusterId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'autonomousVmClusterId'");
            }
            if ((!args || args.certificateGenerationType === undefined) && !opts.urn) {
                throw new Error("Missing required property 'certificateGenerationType'");
            }
            resourceInputs["autonomousVmClusterId"] = args ? args.autonomousVmClusterId : undefined;
            resourceInputs["caBundleId"] = args ? args.caBundleId : undefined;
            resourceInputs["certificateAuthorityId"] = args ? args.certificateAuthorityId : undefined;
            resourceInputs["certificateGenerationType"] = args ? args.certificateGenerationType : undefined;
            resourceInputs["certificateId"] = args ? args.certificateId : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(AutonomousVmClusterOrdsCertificateManagement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AutonomousVmClusterOrdsCertificateManagement resources.
 */
export interface AutonomousVmClusterOrdsCertificateManagementState {
    /**
     * The autonomous VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    autonomousVmClusterId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the certificate bundle.
     */
    caBundleId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the certificate authority.
     */
    certificateAuthorityId?: pulumi.Input<string>;
    /**
     * Specify SYSTEM for using Oracle managed certificates. Specify BYOC when you want to bring your own certificate.
     */
    certificateGenerationType?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the certificate to use. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    certificateId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AutonomousVmClusterOrdsCertificateManagement resource.
 */
export interface AutonomousVmClusterOrdsCertificateManagementArgs {
    /**
     * The autonomous VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     */
    autonomousVmClusterId: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the certificate bundle.
     */
    caBundleId?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the certificate authority.
     */
    certificateAuthorityId?: pulumi.Input<string>;
    /**
     * Specify SYSTEM for using Oracle managed certificates. Specify BYOC when you want to bring your own certificate.
     */
    certificateGenerationType: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the certificate to use. 
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    certificateId?: pulumi.Input<string>;
}
