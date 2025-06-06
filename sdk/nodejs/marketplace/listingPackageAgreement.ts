// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides details about a specific Listing Package Agreement resource in Oracle Cloud Infrastructure Marketplace service.
 *
 * This resource can be used to retrieve the time-based signature of terms of use agreement for a package that can be used to
 * accept the agreement.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testListingPackageAgreement = new oci.marketplace.ListingPackageAgreement("test_listing_package_agreement", {
 *     agreementId: testAgreement.id,
 *     listingId: testListing.id,
 *     packageVersion: listingPackageAgreementPackageVersion,
 *     compartmentId: compartmentId,
 * });
 * ```
 *
 * ## Import
 *
 * Import is not supported for this resource.
 */
export class ListingPackageAgreement extends pulumi.CustomResource {
    /**
     * Get an existing ListingPackageAgreement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ListingPackageAgreementState, opts?: pulumi.CustomResourceOptions): ListingPackageAgreement {
        return new ListingPackageAgreement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Marketplace/listingPackageAgreement:ListingPackageAgreement';

    /**
     * Returns true if the given object is an instance of ListingPackageAgreement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ListingPackageAgreement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ListingPackageAgreement.__pulumiType;
    }

    /**
     * The unique identifier for the agreement.
     */
    public readonly agreementId!: pulumi.Output<string>;
    /**
     * Who authored the agreement.
     */
    public /*out*/ readonly author!: pulumi.Output<string>;
    /**
     * The unique identifier for the compartment, required in gov regions.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * The content URL of the agreement.
     */
    public /*out*/ readonly contentUrl!: pulumi.Output<string>;
    /**
     * The unique identifier for the listing.
     */
    public readonly listingId!: pulumi.Output<string>;
    /**
     * The version of the package. Package versions are unique within a listing.
     */
    public readonly packageVersion!: pulumi.Output<string>;
    /**
     * Textual prompt to read and accept the agreement.
     */
    public /*out*/ readonly prompt!: pulumi.Output<string>;
    /**
     * A time-based signature that can be used to accept an agreement or remove a previously accepted agreement from the list that Marketplace checks before a deployment.
     */
    public /*out*/ readonly signature!: pulumi.Output<string>;

    /**
     * Create a ListingPackageAgreement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ListingPackageAgreementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ListingPackageAgreementArgs | ListingPackageAgreementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ListingPackageAgreementState | undefined;
            resourceInputs["agreementId"] = state ? state.agreementId : undefined;
            resourceInputs["author"] = state ? state.author : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["contentUrl"] = state ? state.contentUrl : undefined;
            resourceInputs["listingId"] = state ? state.listingId : undefined;
            resourceInputs["packageVersion"] = state ? state.packageVersion : undefined;
            resourceInputs["prompt"] = state ? state.prompt : undefined;
            resourceInputs["signature"] = state ? state.signature : undefined;
        } else {
            const args = argsOrState as ListingPackageAgreementArgs | undefined;
            if ((!args || args.agreementId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'agreementId'");
            }
            if ((!args || args.listingId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'listingId'");
            }
            if ((!args || args.packageVersion === undefined) && !opts.urn) {
                throw new Error("Missing required property 'packageVersion'");
            }
            resourceInputs["agreementId"] = args ? args.agreementId : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["listingId"] = args ? args.listingId : undefined;
            resourceInputs["packageVersion"] = args ? args.packageVersion : undefined;
            resourceInputs["author"] = undefined /*out*/;
            resourceInputs["contentUrl"] = undefined /*out*/;
            resourceInputs["prompt"] = undefined /*out*/;
            resourceInputs["signature"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ListingPackageAgreement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ListingPackageAgreement resources.
 */
export interface ListingPackageAgreementState {
    /**
     * The unique identifier for the agreement.
     */
    agreementId?: pulumi.Input<string>;
    /**
     * Who authored the agreement.
     */
    author?: pulumi.Input<string>;
    /**
     * The unique identifier for the compartment, required in gov regions.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The content URL of the agreement.
     */
    contentUrl?: pulumi.Input<string>;
    /**
     * The unique identifier for the listing.
     */
    listingId?: pulumi.Input<string>;
    /**
     * The version of the package. Package versions are unique within a listing.
     */
    packageVersion?: pulumi.Input<string>;
    /**
     * Textual prompt to read and accept the agreement.
     */
    prompt?: pulumi.Input<string>;
    /**
     * A time-based signature that can be used to accept an agreement or remove a previously accepted agreement from the list that Marketplace checks before a deployment.
     */
    signature?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ListingPackageAgreement resource.
 */
export interface ListingPackageAgreementArgs {
    /**
     * The unique identifier for the agreement.
     */
    agreementId: pulumi.Input<string>;
    /**
     * The unique identifier for the compartment, required in gov regions.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * The unique identifier for the listing.
     */
    listingId: pulumi.Input<string>;
    /**
     * The version of the package. Package versions are unique within a listing.
     */
    packageVersion: pulumi.Input<string>;
}
