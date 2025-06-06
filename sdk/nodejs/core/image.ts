// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Image resource in Oracle Cloud Infrastructure Core service.
 *
 * Creates a boot disk image for the specified instance or imports an exported image from the Oracle Cloud Infrastructure Object Storage service.
 *
 * When creating a new image, you must provide the OCID of the instance you want to use as the basis for the image, and
 * the OCID of the compartment containing that instance. For more information about images,
 * see [Managing Custom Images](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/managingcustomimages.htm).
 *
 * When importing an exported image from Object Storage, you specify the source information
 * in [ImageSourceDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/requests/ImageSourceDetails).
 *
 * When importing an image based on the namespace, bucket name, and object name,
 * use [ImageSourceViaObjectStorageTupleDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/requests/ImageSourceViaObjectStorageTupleDetails).
 *
 * When importing an image based on the Object Storage URL, use
 * [ImageSourceViaObjectStorageUriDetails](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/requests/ImageSourceViaObjectStorageUriDetails).
 * See [Object Storage URLs](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/imageimportexport.htm#URLs) and [Using Pre-Authenticated Requests](https://docs.cloud.oracle.com/iaas/Content/Object/Tasks/usingpreauthenticatedrequests.htm)
 * for constructing URLs for image import/export.
 *
 * For more information about importing exported images, see
 * [Image Import/Export](https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/imageimportexport.htm).
 *
 * You may optionally specify a *display name* for the image, which is simply a friendly name or description.
 * It does not have to be unique, and you can change it. See [UpdateImage](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/Image/UpdateImage).
 * Avoid entering confidential information.
 *
 * ## Example Usage
 *
 * ### Create image from instance in tenancy
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testImage = new oci.core.Image("test_image", {
 *     compartmentId: compartmentId,
 *     instanceId: testInstance.id,
 *     definedTags: {
 *         "Operations.CostCenter": "42",
 *     },
 *     displayName: imageDisplayName,
 *     launchMode: imageLaunchMode,
 *     freeformTags: {
 *         Department: "Finance",
 *     },
 * });
 * ```
 *
 * ### Create image from exported image via direct access to object store
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testImage = new oci.core.Image("test_image", {
 *     compartmentId: compartmentId,
 *     displayName: imageDisplayName,
 *     launchMode: imageLaunchMode,
 *     imageSourceDetails: {
 *         sourceType: "objectStorageTuple",
 *         bucketName: bucketName,
 *         namespaceName: namespace,
 *         objectName: objectName,
 *         operatingSystem: imageImageSourceDetailsOperatingSystem,
 *         operatingSystemVersion: imageImageSourceDetailsOperatingSystemVersion,
 *         sourceImageType: sourceImageType,
 *     },
 * });
 * ```
 *
 * ### Create image from exported image at publicly accessible uri
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testImage = new oci.core.Image("test_image", {
 *     compartmentId: compartmentId,
 *     displayName: imageDisplayName,
 *     launchMode: imageLaunchMode,
 *     imageSourceDetails: {
 *         sourceType: "objectStorageUri",
 *         sourceUri: sourceUri,
 *         operatingSystem: imageImageSourceDetailsOperatingSystem,
 *         operatingSystemVersion: imageImageSourceDetailsOperatingSystemVersion,
 *         sourceImageType: sourceImageType,
 *     },
 * });
 * ```
 *
 * ## Import
 *
 * Images can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Core/image:Image test_image "id"
 * ```
 */
export class Image extends pulumi.CustomResource {
    /**
     * Get an existing Image resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ImageState, opts?: pulumi.CustomResourceOptions): Image {
        return new Image(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Core/image:Image';

    /**
     * Returns true if the given object is an instance of Image.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is Image {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === Image.__pulumiType;
    }

    /**
     * Oracle Cloud Agent features supported on the image.
     */
    public /*out*/ readonly agentFeatures!: pulumi.Output<outputs.Core.ImageAgentFeature[]>;
    /**
     * The OCID of the image originally used to launch the instance.
     */
    public /*out*/ readonly baseImageId!: pulumi.Output<string>;
    /**
     * The size of the internal storage for this image that is subject to billing (1 GB = 1,073,741,824 bytes).  Example: `100`
     */
    public /*out*/ readonly billableSizeInGbs!: pulumi.Output<string>;
    /**
     * (Updatable) The OCID of the compartment you want the image to be created in.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * Whether instances launched with this image can be used to create new images. For example, you cannot create an image of an Oracle Database instance.  Example: `true`
     */
    public /*out*/ readonly createImageAllowed!: pulumi.Output<boolean>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: string}>;
    /**
     * (Updatable) A user-friendly name for the image. It does not have to be unique, and it's changeable. Avoid entering confidential information.
     *
     * You cannot use a platform image name as a custom image name.
     *
     * Example: `My Oracle Linux image`
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: string}>;
    public readonly imageSourceDetails!: pulumi.Output<outputs.Core.ImageImageSourceDetails | undefined>;
    /**
     * The OCID of the instance you want to use as the basis for the image.
     */
    public readonly instanceId!: pulumi.Output<string | undefined>;
    /**
     * Specifies the configuration mode for launching virtual machine (VM) instances. The configuration modes are:
     * * `NATIVE` - VM instances launch with iSCSI boot and VFIO devices. The default value for platform images.
     * * `EMULATED` - VM instances launch with emulated devices, such as the E1000 network driver and emulated SCSI disk controller.
     * * `PARAVIRTUALIZED` - VM instances launch with paravirtualized devices using VirtIO drivers.
     * * `CUSTOM` - VM instances launch with custom configuration settings specified in the `LaunchOptions` parameter.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly launchMode!: pulumi.Output<string>;
    /**
     * Options for tuning the compatibility and performance of VM shapes. The values that you specify override any default values.
     */
    public /*out*/ readonly launchOptions!: pulumi.Output<outputs.Core.ImageLaunchOption[]>;
    /**
     * The listing type of the image. The default value is "NONE".
     */
    public /*out*/ readonly listingType!: pulumi.Output<string>;
    /**
     * The image's operating system.  Example: `Oracle Linux`
     */
    public /*out*/ readonly operatingSystem!: pulumi.Output<string>;
    /**
     * The image's operating system version.  Example: `7.2`
     */
    public /*out*/ readonly operatingSystemVersion!: pulumi.Output<string>;
    /**
     * The boot volume size for an instance launched from this image (1 MB = 1,048,576 bytes). Note this is not the same as the size of the image when it was exported or the actual size of the image.  Example: `47694`
     */
    public /*out*/ readonly sizeInMbs!: pulumi.Output<string>;
    /**
     * The current state of the image.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The date and time the image was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;

    /**
     * Create a Image resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ImageArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ImageArgs | ImageState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ImageState | undefined;
            resourceInputs["agentFeatures"] = state ? state.agentFeatures : undefined;
            resourceInputs["baseImageId"] = state ? state.baseImageId : undefined;
            resourceInputs["billableSizeInGbs"] = state ? state.billableSizeInGbs : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["createImageAllowed"] = state ? state.createImageAllowed : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["imageSourceDetails"] = state ? state.imageSourceDetails : undefined;
            resourceInputs["instanceId"] = state ? state.instanceId : undefined;
            resourceInputs["launchMode"] = state ? state.launchMode : undefined;
            resourceInputs["launchOptions"] = state ? state.launchOptions : undefined;
            resourceInputs["listingType"] = state ? state.listingType : undefined;
            resourceInputs["operatingSystem"] = state ? state.operatingSystem : undefined;
            resourceInputs["operatingSystemVersion"] = state ? state.operatingSystemVersion : undefined;
            resourceInputs["sizeInMbs"] = state ? state.sizeInMbs : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
        } else {
            const args = argsOrState as ImageArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["imageSourceDetails"] = args ? args.imageSourceDetails : undefined;
            resourceInputs["instanceId"] = args ? args.instanceId : undefined;
            resourceInputs["launchMode"] = args ? args.launchMode : undefined;
            resourceInputs["agentFeatures"] = undefined /*out*/;
            resourceInputs["baseImageId"] = undefined /*out*/;
            resourceInputs["billableSizeInGbs"] = undefined /*out*/;
            resourceInputs["createImageAllowed"] = undefined /*out*/;
            resourceInputs["launchOptions"] = undefined /*out*/;
            resourceInputs["listingType"] = undefined /*out*/;
            resourceInputs["operatingSystem"] = undefined /*out*/;
            resourceInputs["operatingSystemVersion"] = undefined /*out*/;
            resourceInputs["sizeInMbs"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(Image.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering Image resources.
 */
export interface ImageState {
    /**
     * Oracle Cloud Agent features supported on the image.
     */
    agentFeatures?: pulumi.Input<pulumi.Input<inputs.Core.ImageAgentFeature>[]>;
    /**
     * The OCID of the image originally used to launch the instance.
     */
    baseImageId?: pulumi.Input<string>;
    /**
     * The size of the internal storage for this image that is subject to billing (1 GB = 1,073,741,824 bytes).  Example: `100`
     */
    billableSizeInGbs?: pulumi.Input<string>;
    /**
     * (Updatable) The OCID of the compartment you want the image to be created in.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Whether instances launched with this image can be used to create new images. For example, you cannot create an image of an Oracle Database instance.  Example: `true`
     */
    createImageAllowed?: pulumi.Input<boolean>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name for the image. It does not have to be unique, and it's changeable. Avoid entering confidential information.
     *
     * You cannot use a platform image name as a custom image name.
     *
     * Example: `My Oracle Linux image`
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    imageSourceDetails?: pulumi.Input<inputs.Core.ImageImageSourceDetails>;
    /**
     * The OCID of the instance you want to use as the basis for the image.
     */
    instanceId?: pulumi.Input<string>;
    /**
     * Specifies the configuration mode for launching virtual machine (VM) instances. The configuration modes are:
     * * `NATIVE` - VM instances launch with iSCSI boot and VFIO devices. The default value for platform images.
     * * `EMULATED` - VM instances launch with emulated devices, such as the E1000 network driver and emulated SCSI disk controller.
     * * `PARAVIRTUALIZED` - VM instances launch with paravirtualized devices using VirtIO drivers.
     * * `CUSTOM` - VM instances launch with custom configuration settings specified in the `LaunchOptions` parameter.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    launchMode?: pulumi.Input<string>;
    /**
     * Options for tuning the compatibility and performance of VM shapes. The values that you specify override any default values.
     */
    launchOptions?: pulumi.Input<pulumi.Input<inputs.Core.ImageLaunchOption>[]>;
    /**
     * The listing type of the image. The default value is "NONE".
     */
    listingType?: pulumi.Input<string>;
    /**
     * The image's operating system.  Example: `Oracle Linux`
     */
    operatingSystem?: pulumi.Input<string>;
    /**
     * The image's operating system version.  Example: `7.2`
     */
    operatingSystemVersion?: pulumi.Input<string>;
    /**
     * The boot volume size for an instance launched from this image (1 MB = 1,048,576 bytes). Note this is not the same as the size of the image when it was exported or the actual size of the image.  Example: `47694`
     */
    sizeInMbs?: pulumi.Input<string>;
    /**
     * The current state of the image.
     */
    state?: pulumi.Input<string>;
    /**
     * The date and time the image was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     */
    timeCreated?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a Image resource.
 */
export interface ImageArgs {
    /**
     * (Updatable) The OCID of the compartment you want the image to be created in.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
     */
    definedTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    /**
     * (Updatable) A user-friendly name for the image. It does not have to be unique, and it's changeable. Avoid entering confidential information.
     *
     * You cannot use a platform image name as a custom image name.
     *
     * Example: `My Oracle Linux image`
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: pulumi.Input<string>}>;
    imageSourceDetails?: pulumi.Input<inputs.Core.ImageImageSourceDetails>;
    /**
     * The OCID of the instance you want to use as the basis for the image.
     */
    instanceId?: pulumi.Input<string>;
    /**
     * Specifies the configuration mode for launching virtual machine (VM) instances. The configuration modes are:
     * * `NATIVE` - VM instances launch with iSCSI boot and VFIO devices. The default value for platform images.
     * * `EMULATED` - VM instances launch with emulated devices, such as the E1000 network driver and emulated SCSI disk controller.
     * * `PARAVIRTUALIZED` - VM instances launch with paravirtualized devices using VirtIO drivers.
     * * `CUSTOM` - VM instances launch with custom configuration settings specified in the `LaunchOptions` parameter.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    launchMode?: pulumi.Input<string>;
}
