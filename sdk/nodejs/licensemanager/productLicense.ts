// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This resource provides the Product License resource in Oracle Cloud Infrastructure License Manager service.
 *
 * Creates a new product license.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testProductLicense = new oci.licensemanager.ProductLicense("testProductLicense", {
 *     compartmentId: _var.compartment_id,
 *     displayName: _var.product_license_display_name,
 *     isVendorOracle: _var.product_license_is_vendor_oracle,
 *     licenseUnit: _var.product_license_license_unit,
 *     definedTags: {
 *         "foo-namespace.bar-key": "value",
 *     },
 *     freeformTags: {
 *         "bar-key": "value",
 *     },
 *     images: [{
 *         listingId: oci_marketplace_listing.test_listing.id,
 *         packageVersion: _var.product_license_images_package_version,
 *     }],
 *     vendorName: _var.product_license_vendor_name,
 * });
 * ```
 *
 * ## Import
 *
 * ProductLicenses can be imported using the `id`, e.g.
 *
 * ```sh
 *  $ pulumi import oci:LicenseManager/productLicense:ProductLicense test_product_license "id"
 * ```
 */
export class ProductLicense extends pulumi.CustomResource {
    /**
     * Get an existing ProductLicense resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ProductLicenseState, opts?: pulumi.CustomResourceOptions): ProductLicense {
        return new ProductLicense(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:LicenseManager/productLicense:ProductLicense';

    /**
     * Returns true if the given object is an instance of ProductLicense.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ProductLicense {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ProductLicense.__pulumiType;
    }

    /**
     * The number of active license records associated with the product license.
     */
    public /*out*/ readonly activeLicenseRecordCount!: pulumi.Output<number>;
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) where product licenses are created.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    public readonly definedTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * Name of the product license.
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    public readonly freeformTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * (Updatable) The image details associated with the product license.
     */
    public readonly images!: pulumi.Output<outputs.LicenseManager.ProductLicenseImage[]>;
    /**
     * Specifies whether or not the product license is oversubscribed.
     */
    public /*out*/ readonly isOverSubscribed!: pulumi.Output<boolean>;
    /**
     * Specifies if the license unit count is unlimited.
     */
    public /*out*/ readonly isUnlimited!: pulumi.Output<boolean>;
    /**
     * Specifies if the product license vendor is Oracle or a third party.
     */
    public readonly isVendorOracle!: pulumi.Output<boolean>;
    /**
     * The product license unit.
     */
    public readonly licenseUnit!: pulumi.Output<string>;
    /**
     * The current product license state.
     */
    public /*out*/ readonly state!: pulumi.Output<string>;
    /**
     * The current product license status.
     */
    public /*out*/ readonly status!: pulumi.Output<string>;
    /**
     * Status description for the current product license status.
     */
    public /*out*/ readonly statusDescription!: pulumi.Output<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    public /*out*/ readonly systemTags!: pulumi.Output<{[key: string]: any}>;
    /**
     * The time the product license was created. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
     */
    public /*out*/ readonly timeCreated!: pulumi.Output<string>;
    /**
     * The time the product license was updated. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
     */
    public /*out*/ readonly timeUpdated!: pulumi.Output<string>;
    /**
     * The total number of licenses available for the product license, calculated by adding up all the license counts for active license records associated with the product license.
     */
    public /*out*/ readonly totalActiveLicenseUnitCount!: pulumi.Output<number>;
    /**
     * The number of license records associated with the product license.
     */
    public /*out*/ readonly totalLicenseRecordCount!: pulumi.Output<number>;
    /**
     * The number of license units consumed. Updated after each allocation run.
     */
    public /*out*/ readonly totalLicenseUnitsConsumed!: pulumi.Output<number>;
    /**
     * The product license vendor name, for example: Microsoft, RHEL, and so on.
     */
    public readonly vendorName!: pulumi.Output<string>;

    /**
     * Create a ProductLicense resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ProductLicenseArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ProductLicenseArgs | ProductLicenseState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ProductLicenseState | undefined;
            resourceInputs["activeLicenseRecordCount"] = state ? state.activeLicenseRecordCount : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["definedTags"] = state ? state.definedTags : undefined;
            resourceInputs["displayName"] = state ? state.displayName : undefined;
            resourceInputs["freeformTags"] = state ? state.freeformTags : undefined;
            resourceInputs["images"] = state ? state.images : undefined;
            resourceInputs["isOverSubscribed"] = state ? state.isOverSubscribed : undefined;
            resourceInputs["isUnlimited"] = state ? state.isUnlimited : undefined;
            resourceInputs["isVendorOracle"] = state ? state.isVendorOracle : undefined;
            resourceInputs["licenseUnit"] = state ? state.licenseUnit : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["status"] = state ? state.status : undefined;
            resourceInputs["statusDescription"] = state ? state.statusDescription : undefined;
            resourceInputs["systemTags"] = state ? state.systemTags : undefined;
            resourceInputs["timeCreated"] = state ? state.timeCreated : undefined;
            resourceInputs["timeUpdated"] = state ? state.timeUpdated : undefined;
            resourceInputs["totalActiveLicenseUnitCount"] = state ? state.totalActiveLicenseUnitCount : undefined;
            resourceInputs["totalLicenseRecordCount"] = state ? state.totalLicenseRecordCount : undefined;
            resourceInputs["totalLicenseUnitsConsumed"] = state ? state.totalLicenseUnitsConsumed : undefined;
            resourceInputs["vendorName"] = state ? state.vendorName : undefined;
        } else {
            const args = argsOrState as ProductLicenseArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.displayName === undefined) && !opts.urn) {
                throw new Error("Missing required property 'displayName'");
            }
            if ((!args || args.isVendorOracle === undefined) && !opts.urn) {
                throw new Error("Missing required property 'isVendorOracle'");
            }
            if ((!args || args.licenseUnit === undefined) && !opts.urn) {
                throw new Error("Missing required property 'licenseUnit'");
            }
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["definedTags"] = args ? args.definedTags : undefined;
            resourceInputs["displayName"] = args ? args.displayName : undefined;
            resourceInputs["freeformTags"] = args ? args.freeformTags : undefined;
            resourceInputs["images"] = args ? args.images : undefined;
            resourceInputs["isVendorOracle"] = args ? args.isVendorOracle : undefined;
            resourceInputs["licenseUnit"] = args ? args.licenseUnit : undefined;
            resourceInputs["vendorName"] = args ? args.vendorName : undefined;
            resourceInputs["activeLicenseRecordCount"] = undefined /*out*/;
            resourceInputs["isOverSubscribed"] = undefined /*out*/;
            resourceInputs["isUnlimited"] = undefined /*out*/;
            resourceInputs["state"] = undefined /*out*/;
            resourceInputs["status"] = undefined /*out*/;
            resourceInputs["statusDescription"] = undefined /*out*/;
            resourceInputs["systemTags"] = undefined /*out*/;
            resourceInputs["timeCreated"] = undefined /*out*/;
            resourceInputs["timeUpdated"] = undefined /*out*/;
            resourceInputs["totalActiveLicenseUnitCount"] = undefined /*out*/;
            resourceInputs["totalLicenseRecordCount"] = undefined /*out*/;
            resourceInputs["totalLicenseUnitsConsumed"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ProductLicense.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ProductLicense resources.
 */
export interface ProductLicenseState {
    /**
     * The number of active license records associated with the product license.
     */
    activeLicenseRecordCount?: pulumi.Input<number>;
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) where product licenses are created.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Name of the product license.
     */
    displayName?: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The image details associated with the product license.
     */
    images?: pulumi.Input<pulumi.Input<inputs.LicenseManager.ProductLicenseImage>[]>;
    /**
     * Specifies whether or not the product license is oversubscribed.
     */
    isOverSubscribed?: pulumi.Input<boolean>;
    /**
     * Specifies if the license unit count is unlimited.
     */
    isUnlimited?: pulumi.Input<boolean>;
    /**
     * Specifies if the product license vendor is Oracle or a third party.
     */
    isVendorOracle?: pulumi.Input<boolean>;
    /**
     * The product license unit.
     */
    licenseUnit?: pulumi.Input<string>;
    /**
     * The current product license state.
     */
    state?: pulumi.Input<string>;
    /**
     * The current product license status.
     */
    status?: pulumi.Input<string>;
    /**
     * Status description for the current product license status.
     */
    statusDescription?: pulumi.Input<string>;
    /**
     * Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
     */
    systemTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * The time the product license was created. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
     */
    timeCreated?: pulumi.Input<string>;
    /**
     * The time the product license was updated. An [RFC 3339](https://tools.ietf.org/html/rfc3339)-formatted datetime string.
     */
    timeUpdated?: pulumi.Input<string>;
    /**
     * The total number of licenses available for the product license, calculated by adding up all the license counts for active license records associated with the product license.
     */
    totalActiveLicenseUnitCount?: pulumi.Input<number>;
    /**
     * The number of license records associated with the product license.
     */
    totalLicenseRecordCount?: pulumi.Input<number>;
    /**
     * The number of license units consumed. Updated after each allocation run.
     */
    totalLicenseUnitsConsumed?: pulumi.Input<number>;
    /**
     * The product license vendor name, for example: Microsoft, RHEL, and so on.
     */
    vendorName?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ProductLicense resource.
 */
export interface ProductLicenseArgs {
    /**
     * The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) where product licenses are created.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
     */
    definedTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * Name of the product license.
     */
    displayName: pulumi.Input<string>;
    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type, or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
     */
    freeformTags?: pulumi.Input<{[key: string]: any}>;
    /**
     * (Updatable) The image details associated with the product license.
     */
    images?: pulumi.Input<pulumi.Input<inputs.LicenseManager.ProductLicenseImage>[]>;
    /**
     * Specifies if the product license vendor is Oracle or a third party.
     */
    isVendorOracle: pulumi.Input<boolean>;
    /**
     * The product license unit.
     */
    licenseUnit: pulumi.Input<string>;
    /**
     * The product license vendor name, for example: Microsoft, RHEL, and so on.
     */
    vendorName?: pulumi.Input<string>;
}