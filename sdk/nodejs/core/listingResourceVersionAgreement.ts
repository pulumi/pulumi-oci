// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

export class ListingResourceVersionAgreement extends pulumi.CustomResource {
    /**
     * Get an existing ListingResourceVersionAgreement resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: ListingResourceVersionAgreementState, opts?: pulumi.CustomResourceOptions): ListingResourceVersionAgreement {
        return new ListingResourceVersionAgreement(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Core/listingResourceVersionAgreement:ListingResourceVersionAgreement';

    /**
     * Returns true if the given object is an instance of ListingResourceVersionAgreement.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is ListingResourceVersionAgreement {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === ListingResourceVersionAgreement.__pulumiType;
    }

    public /*out*/ readonly eulaLink!: pulumi.Output<string>;
    public readonly listingId!: pulumi.Output<string>;
    public readonly listingResourceVersion!: pulumi.Output<string>;
    public /*out*/ readonly oracleTermsOfUseLink!: pulumi.Output<string>;
    public /*out*/ readonly signature!: pulumi.Output<string>;
    public /*out*/ readonly timeRetrieved!: pulumi.Output<string>;

    /**
     * Create a ListingResourceVersionAgreement resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: ListingResourceVersionAgreementArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: ListingResourceVersionAgreementArgs | ListingResourceVersionAgreementState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as ListingResourceVersionAgreementState | undefined;
            resourceInputs["eulaLink"] = state ? state.eulaLink : undefined;
            resourceInputs["listingId"] = state ? state.listingId : undefined;
            resourceInputs["listingResourceVersion"] = state ? state.listingResourceVersion : undefined;
            resourceInputs["oracleTermsOfUseLink"] = state ? state.oracleTermsOfUseLink : undefined;
            resourceInputs["signature"] = state ? state.signature : undefined;
            resourceInputs["timeRetrieved"] = state ? state.timeRetrieved : undefined;
        } else {
            const args = argsOrState as ListingResourceVersionAgreementArgs | undefined;
            if ((!args || args.listingId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'listingId'");
            }
            if ((!args || args.listingResourceVersion === undefined) && !opts.urn) {
                throw new Error("Missing required property 'listingResourceVersion'");
            }
            resourceInputs["listingId"] = args ? args.listingId : undefined;
            resourceInputs["listingResourceVersion"] = args ? args.listingResourceVersion : undefined;
            resourceInputs["eulaLink"] = undefined /*out*/;
            resourceInputs["oracleTermsOfUseLink"] = undefined /*out*/;
            resourceInputs["signature"] = undefined /*out*/;
            resourceInputs["timeRetrieved"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(ListingResourceVersionAgreement.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering ListingResourceVersionAgreement resources.
 */
export interface ListingResourceVersionAgreementState {
    eulaLink?: pulumi.Input<string>;
    listingId?: pulumi.Input<string>;
    listingResourceVersion?: pulumi.Input<string>;
    oracleTermsOfUseLink?: pulumi.Input<string>;
    signature?: pulumi.Input<string>;
    timeRetrieved?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a ListingResourceVersionAgreement resource.
 */
export interface ListingResourceVersionAgreementArgs {
    listingId: pulumi.Input<string>;
    listingResourceVersion: pulumi.Input<string>;
}