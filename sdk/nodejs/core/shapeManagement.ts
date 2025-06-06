// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Shape Management resource in Oracle Cloud Infrastructure Core service.
 *
 * Add/Remove the specified shape from the compatible shapes list for the image.
 */
export class ShapeManagement extends pulumi.CustomResource {
    /**
     * Get an existing ShapeManagement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ShapeManagementState, opts?: pulumi.CustomResourceOptions): ShapeManagement {
        return new ShapeManagement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Core/shapeManagement:ShapeManagement';

    /**
     * Returns true if the given object is an instance of ShapeManagement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ShapeManagement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ShapeManagement.__pulumiType;
    }

    /**
     * The OCID of the compartment containing the image.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The OCID of the Image to which the shape should be added.
     */
    public readonly imageId!: pulumi.Output<string>;
    /**
     * The compatible shape that is to be added to the compatible shapes list for the image.
     */
    public readonly shapeName!: pulumi.Output<string>;

    /**
     * Create a ShapeManagement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ShapeManagementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ShapeManagementArgs | ShapeManagementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ShapeManagementState | undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["imageId"] = state ? state.imageId : undefined;
            resourceInputs["shapeName"] = state ? state.shapeName : undefined;
        } else {
            const args = argsOrState as ShapeManagementArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.imageId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'imageId'");
            }
            if ((!args || args.shapeName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'shapeName'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["imageId"] = args ? args.imageId : undefined;
            resourceInputs["shapeName"] = args ? args.shapeName : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ShapeManagement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ShapeManagement resources.
 */
export interface ShapeManagementState {
    /**
     * The OCID of the compartment containing the image.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The OCID of the Image to which the shape should be added.
     */
    imageId?: pulumi.Input<string>;
    /**
     * The compatible shape that is to be added to the compatible shapes list for the image.
     */
    shapeName?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ShapeManagement resource.
 */
export interface ShapeManagementArgs {
    /**
     * The OCID of the compartment containing the image.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The OCID of the Image to which the shape should be added.
     */
    imageId: pulumi.Input<string>;
    /**
     * The compatible shape that is to be added to the compatible shapes list for the image.
     */
    shapeName: pulumi.Input<string>;
}
