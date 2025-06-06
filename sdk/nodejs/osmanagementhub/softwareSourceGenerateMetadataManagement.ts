// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Software Source Generate Metadata Management resource in Oracle Cloud Infrastructure Os Management Hub service.
 *
 * Regenerates metadata for the specified custom software source.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSoftwareSourceGenerateMetadataManagement = new oci.osmanagementhub.SoftwareSourceGenerateMetadataManagement("test_software_source_generate_metadata_management", {softwareSourceId: testSoftwareSource.id});
 * ```
 *
 * ## Import
 *
 * SoftwareSourceGenerateMetadataManagement can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:OsManagementHub/softwareSourceGenerateMetadataManagement:SoftwareSourceGenerateMetadataManagement test_software_source_generate_metadata_management "id"
 * ```
 */
export class SoftwareSourceGenerateMetadataManagement extends pulumi.CustomResource {
    /**
     * Get an existing SoftwareSourceGenerateMetadataManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: SoftwareSourceGenerateMetadataManagementState, opts?: pulumi.CustomResourceOptions): SoftwareSourceGenerateMetadataManagement {
        return new SoftwareSourceGenerateMetadataManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:OsManagementHub/softwareSourceGenerateMetadataManagement:SoftwareSourceGenerateMetadataManagement';

    /**
     * Returns true if the given object is an instance of SoftwareSourceGenerateMetadataManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is SoftwareSourceGenerateMetadataManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === SoftwareSourceGenerateMetadataManagement.__pulumiType;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly softwareSourceId!: pulumi.Output<string>;

    /**
     * Create a SoftwareSourceGenerateMetadataManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: SoftwareSourceGenerateMetadataManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: SoftwareSourceGenerateMetadataManagementArgs | SoftwareSourceGenerateMetadataManagementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as SoftwareSourceGenerateMetadataManagementState | undefined;
            resourceInputs["softwareSourceId"] = state ? state.softwareSourceId : undefined;
        } else {
            const args = argsOrState as SoftwareSourceGenerateMetadataManagementArgs | undefined;
            if ((!args || args.softwareSourceId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'softwareSourceId'");
            }
            resourceInputs["softwareSourceId"] = args ? args.softwareSourceId : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(SoftwareSourceGenerateMetadataManagement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering SoftwareSourceGenerateMetadataManagement resources.
 */
export interface SoftwareSourceGenerateMetadataManagementState {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    softwareSourceId?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a SoftwareSourceGenerateMetadataManagement resource.
 */
export interface SoftwareSourceGenerateMetadataManagementArgs {
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    softwareSourceId: pulumi.Input<string>;
}
