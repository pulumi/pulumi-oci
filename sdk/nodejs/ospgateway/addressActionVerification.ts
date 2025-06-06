// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This resource provides the Address Action Verification resource in Oracle Cloud Infrastructure Osp Gateway service.
 *
 * Verify address
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAddressActionVerification = new oci.ospgateway.AddressActionVerification("test_address_action_verification", {
 *     compartmentId: compartmentId,
 *     ospHomeRegion: addressActionVerificationOspHomeRegion,
 *     addressKey: addressActionVerificationAddressKey,
 *     city: addressActionVerificationCity,
 *     companyName: addressActionVerificationCompanyName,
 *     contributorClass: addressActionVerificationContributorClass,
 *     country: addressActionVerificationCountry,
 *     county: addressActionVerificationCounty,
 *     departmentName: addressActionVerificationDepartmentName,
 *     emailAddress: addressActionVerificationEmailAddress,
 *     firstName: addressActionVerificationFirstName,
 *     internalNumber: addressActionVerificationInternalNumber,
 *     jobTitle: addressActionVerificationJobTitle,
 *     lastName: addressActionVerificationLastName,
 *     line1: addressActionVerificationLine1,
 *     line2: addressActionVerificationLine2,
 *     line3: addressActionVerificationLine3,
 *     line4: addressActionVerificationLine4,
 *     middleName: addressActionVerificationMiddleName,
 *     municipalInscription: addressActionVerificationMunicipalInscription,
 *     phoneCountryCode: addressActionVerificationPhoneCountryCode,
 *     phoneNumber: addressActionVerificationPhoneNumber,
 *     postalCode: addressActionVerificationPostalCode,
 *     province: addressActionVerificationProvince,
 *     state: addressActionVerificationState,
 *     stateInscription: addressActionVerificationStateInscription,
 *     streetName: addressActionVerificationStreetName,
 *     streetNumber: addressActionVerificationStreetNumber,
 * });
 * ```
 *
 * ## Import
 *
 * AddressActionVerifications can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:OspGateway/addressActionVerification:AddressActionVerification test_address_action_verification "id"
 * ```
 */
export class AddressActionVerification extends pulumi.CustomResource {
    /**
     * Get an existing AddressActionVerification resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: AddressActionVerificationState, opts?: pulumi.CustomResourceOptions): AddressActionVerification {
        return new AddressActionVerification(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:OspGateway/addressActionVerification:AddressActionVerification';

    /**
     * Returns true if the given object is an instance of AddressActionVerification.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is AddressActionVerification {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === AddressActionVerification.__pulumiType;
    }

    /**
     * Address identifier.
     */
    public readonly addressKey!: pulumi.Output<string>;
    /**
     * Address details model.
     */
    public /*out*/ readonly addresses!: pulumi.Output<outputs.OspGateway.AddressActionVerificationAddress[]>;
    /**
     * Name of the city.
     */
    public readonly city!: pulumi.Output<string>;
    /**
     * Name of the customer company.
     */
    public readonly companyName!: pulumi.Output<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    public readonly compartmentId!: pulumi.Output<string>;
    /**
     * Contributor class of the customer company.
     */
    public readonly contributorClass!: pulumi.Output<string>;
    /**
     * Country of the address.
     */
    public readonly country!: pulumi.Output<string>;
    /**
     * County of the address.
     */
    public readonly county!: pulumi.Output<string>;
    /**
     * Department name of the customer company.
     */
    public readonly departmentName!: pulumi.Output<string>;
    /**
     * Contact person email address.
     */
    public readonly emailAddress!: pulumi.Output<string>;
    /**
     * First name of the contact person.
     */
    public readonly firstName!: pulumi.Output<string>;
    /**
     * Internal number of the customer company.
     */
    public readonly internalNumber!: pulumi.Output<string>;
    /**
     * Job title of the contact person.
     */
    public readonly jobTitle!: pulumi.Output<string>;
    /**
     * Last name of the contact person.
     */
    public readonly lastName!: pulumi.Output<string>;
    /**
     * Address line 1.
     */
    public readonly line1!: pulumi.Output<string>;
    /**
     * Address line 2.
     */
    public readonly line2!: pulumi.Output<string>;
    /**
     * Address line 3.
     */
    public readonly line3!: pulumi.Output<string>;
    /**
     * Address line 4.
     */
    public readonly line4!: pulumi.Output<string>;
    /**
     * Middle name of the contact person.
     */
    public readonly middleName!: pulumi.Output<string>;
    /**
     * Municipal Inscription.
     */
    public readonly municipalInscription!: pulumi.Output<string>;
    /**
     * The home region's public name of the logged in user.
     */
    public readonly ospHomeRegion!: pulumi.Output<string>;
    /**
     * Phone country code of the contact person.
     */
    public readonly phoneCountryCode!: pulumi.Output<string>;
    /**
     * Phone number of the contact person.
     */
    public readonly phoneNumber!: pulumi.Output<string>;
    /**
     * Post code of the address.
     */
    public readonly postalCode!: pulumi.Output<string>;
    /**
     * Province of the address.
     */
    public readonly province!: pulumi.Output<string>;
    /**
     * Address quality type.
     */
    public /*out*/ readonly quality!: pulumi.Output<string>;
    /**
     * State of the address.
     */
    public readonly state!: pulumi.Output<string>;
    /**
     * State Inscription.
     */
    public readonly stateInscription!: pulumi.Output<string>;
    /**
     * Street name of the address.
     */
    public readonly streetName!: pulumi.Output<string>;
    /**
     * Street number of the address.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly streetNumber!: pulumi.Output<string>;
    /**
     * Address verification code.
     */
    public /*out*/ readonly verificationCode!: pulumi.Output<string>;

    /**
     * Create a AddressActionVerification resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: AddressActionVerificationArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: AddressActionVerificationArgs | AddressActionVerificationState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as AddressActionVerificationState | undefined;
            resourceInputs["addressKey"] = state ? state.addressKey : undefined;
            resourceInputs["addresses"] = state ? state.addresses : undefined;
            resourceInputs["city"] = state ? state.city : undefined;
            resourceInputs["companyName"] = state ? state.companyName : undefined;
            resourceInputs["compartmentId"] = state ? state.compartmentId : undefined;
            resourceInputs["contributorClass"] = state ? state.contributorClass : undefined;
            resourceInputs["country"] = state ? state.country : undefined;
            resourceInputs["county"] = state ? state.county : undefined;
            resourceInputs["departmentName"] = state ? state.departmentName : undefined;
            resourceInputs["emailAddress"] = state ? state.emailAddress : undefined;
            resourceInputs["firstName"] = state ? state.firstName : undefined;
            resourceInputs["internalNumber"] = state ? state.internalNumber : undefined;
            resourceInputs["jobTitle"] = state ? state.jobTitle : undefined;
            resourceInputs["lastName"] = state ? state.lastName : undefined;
            resourceInputs["line1"] = state ? state.line1 : undefined;
            resourceInputs["line2"] = state ? state.line2 : undefined;
            resourceInputs["line3"] = state ? state.line3 : undefined;
            resourceInputs["line4"] = state ? state.line4 : undefined;
            resourceInputs["middleName"] = state ? state.middleName : undefined;
            resourceInputs["municipalInscription"] = state ? state.municipalInscription : undefined;
            resourceInputs["ospHomeRegion"] = state ? state.ospHomeRegion : undefined;
            resourceInputs["phoneCountryCode"] = state ? state.phoneCountryCode : undefined;
            resourceInputs["phoneNumber"] = state ? state.phoneNumber : undefined;
            resourceInputs["postalCode"] = state ? state.postalCode : undefined;
            resourceInputs["province"] = state ? state.province : undefined;
            resourceInputs["quality"] = state ? state.quality : undefined;
            resourceInputs["state"] = state ? state.state : undefined;
            resourceInputs["stateInscription"] = state ? state.stateInscription : undefined;
            resourceInputs["streetName"] = state ? state.streetName : undefined;
            resourceInputs["streetNumber"] = state ? state.streetNumber : undefined;
            resourceInputs["verificationCode"] = state ? state.verificationCode : undefined;
        } else {
            const args = argsOrState as AddressActionVerificationArgs | undefined;
            if ((!args || args.compartmentId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'compartmentId'");
            }
            if ((!args || args.ospHomeRegion === undefined) && !opts.urn) {
                throw new Error("Missing required property 'ospHomeRegion'");
            }
            resourceInputs["addressKey"] = args ? args.addressKey : undefined;
            resourceInputs["city"] = args ? args.city : undefined;
            resourceInputs["companyName"] = args ? args.companyName : undefined;
            resourceInputs["compartmentId"] = args ? args.compartmentId : undefined;
            resourceInputs["contributorClass"] = args ? args.contributorClass : undefined;
            resourceInputs["country"] = args ? args.country : undefined;
            resourceInputs["county"] = args ? args.county : undefined;
            resourceInputs["departmentName"] = args ? args.departmentName : undefined;
            resourceInputs["emailAddress"] = args ? args.emailAddress : undefined;
            resourceInputs["firstName"] = args ? args.firstName : undefined;
            resourceInputs["internalNumber"] = args ? args.internalNumber : undefined;
            resourceInputs["jobTitle"] = args ? args.jobTitle : undefined;
            resourceInputs["lastName"] = args ? args.lastName : undefined;
            resourceInputs["line1"] = args ? args.line1 : undefined;
            resourceInputs["line2"] = args ? args.line2 : undefined;
            resourceInputs["line3"] = args ? args.line3 : undefined;
            resourceInputs["line4"] = args ? args.line4 : undefined;
            resourceInputs["middleName"] = args ? args.middleName : undefined;
            resourceInputs["municipalInscription"] = args ? args.municipalInscription : undefined;
            resourceInputs["ospHomeRegion"] = args ? args.ospHomeRegion : undefined;
            resourceInputs["phoneCountryCode"] = args ? args.phoneCountryCode : undefined;
            resourceInputs["phoneNumber"] = args ? args.phoneNumber : undefined;
            resourceInputs["postalCode"] = args ? args.postalCode : undefined;
            resourceInputs["province"] = args ? args.province : undefined;
            resourceInputs["state"] = args ? args.state : undefined;
            resourceInputs["stateInscription"] = args ? args.stateInscription : undefined;
            resourceInputs["streetName"] = args ? args.streetName : undefined;
            resourceInputs["streetNumber"] = args ? args.streetNumber : undefined;
            resourceInputs["addresses"] = undefined /*out*/;
            resourceInputs["quality"] = undefined /*out*/;
            resourceInputs["verificationCode"] = undefined /*out*/;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(AddressActionVerification.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering AddressActionVerification resources.
 */
export interface AddressActionVerificationState {
    /**
     * Address identifier.
     */
    addressKey?: pulumi.Input<string>;
    /**
     * Address details model.
     */
    addresses?: pulumi.Input<pulumi.Input<inputs.OspGateway.AddressActionVerificationAddress>[]>;
    /**
     * Name of the city.
     */
    city?: pulumi.Input<string>;
    /**
     * Name of the customer company.
     */
    companyName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId?: pulumi.Input<string>;
    /**
     * Contributor class of the customer company.
     */
    contributorClass?: pulumi.Input<string>;
    /**
     * Country of the address.
     */
    country?: pulumi.Input<string>;
    /**
     * County of the address.
     */
    county?: pulumi.Input<string>;
    /**
     * Department name of the customer company.
     */
    departmentName?: pulumi.Input<string>;
    /**
     * Contact person email address.
     */
    emailAddress?: pulumi.Input<string>;
    /**
     * First name of the contact person.
     */
    firstName?: pulumi.Input<string>;
    /**
     * Internal number of the customer company.
     */
    internalNumber?: pulumi.Input<string>;
    /**
     * Job title of the contact person.
     */
    jobTitle?: pulumi.Input<string>;
    /**
     * Last name of the contact person.
     */
    lastName?: pulumi.Input<string>;
    /**
     * Address line 1.
     */
    line1?: pulumi.Input<string>;
    /**
     * Address line 2.
     */
    line2?: pulumi.Input<string>;
    /**
     * Address line 3.
     */
    line3?: pulumi.Input<string>;
    /**
     * Address line 4.
     */
    line4?: pulumi.Input<string>;
    /**
     * Middle name of the contact person.
     */
    middleName?: pulumi.Input<string>;
    /**
     * Municipal Inscription.
     */
    municipalInscription?: pulumi.Input<string>;
    /**
     * The home region's public name of the logged in user.
     */
    ospHomeRegion?: pulumi.Input<string>;
    /**
     * Phone country code of the contact person.
     */
    phoneCountryCode?: pulumi.Input<string>;
    /**
     * Phone number of the contact person.
     */
    phoneNumber?: pulumi.Input<string>;
    /**
     * Post code of the address.
     */
    postalCode?: pulumi.Input<string>;
    /**
     * Province of the address.
     */
    province?: pulumi.Input<string>;
    /**
     * Address quality type.
     */
    quality?: pulumi.Input<string>;
    /**
     * State of the address.
     */
    state?: pulumi.Input<string>;
    /**
     * State Inscription.
     */
    stateInscription?: pulumi.Input<string>;
    /**
     * Street name of the address.
     */
    streetName?: pulumi.Input<string>;
    /**
     * Street number of the address.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    streetNumber?: pulumi.Input<string>;
    /**
     * Address verification code.
     */
    verificationCode?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a AddressActionVerification resource.
 */
export interface AddressActionVerificationArgs {
    /**
     * Address identifier.
     */
    addressKey?: pulumi.Input<string>;
    /**
     * Name of the city.
     */
    city?: pulumi.Input<string>;
    /**
     * Name of the customer company.
     */
    companyName?: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * Contributor class of the customer company.
     */
    contributorClass?: pulumi.Input<string>;
    /**
     * Country of the address.
     */
    country?: pulumi.Input<string>;
    /**
     * County of the address.
     */
    county?: pulumi.Input<string>;
    /**
     * Department name of the customer company.
     */
    departmentName?: pulumi.Input<string>;
    /**
     * Contact person email address.
     */
    emailAddress?: pulumi.Input<string>;
    /**
     * First name of the contact person.
     */
    firstName?: pulumi.Input<string>;
    /**
     * Internal number of the customer company.
     */
    internalNumber?: pulumi.Input<string>;
    /**
     * Job title of the contact person.
     */
    jobTitle?: pulumi.Input<string>;
    /**
     * Last name of the contact person.
     */
    lastName?: pulumi.Input<string>;
    /**
     * Address line 1.
     */
    line1?: pulumi.Input<string>;
    /**
     * Address line 2.
     */
    line2?: pulumi.Input<string>;
    /**
     * Address line 3.
     */
    line3?: pulumi.Input<string>;
    /**
     * Address line 4.
     */
    line4?: pulumi.Input<string>;
    /**
     * Middle name of the contact person.
     */
    middleName?: pulumi.Input<string>;
    /**
     * Municipal Inscription.
     */
    municipalInscription?: pulumi.Input<string>;
    /**
     * The home region's public name of the logged in user.
     */
    ospHomeRegion: pulumi.Input<string>;
    /**
     * Phone country code of the contact person.
     */
    phoneCountryCode?: pulumi.Input<string>;
    /**
     * Phone number of the contact person.
     */
    phoneNumber?: pulumi.Input<string>;
    /**
     * Post code of the address.
     */
    postalCode?: pulumi.Input<string>;
    /**
     * Province of the address.
     */
    province?: pulumi.Input<string>;
    /**
     * State of the address.
     */
    state?: pulumi.Input<string>;
    /**
     * State Inscription.
     */
    stateInscription?: pulumi.Input<string>;
    /**
     * Street name of the address.
     */
    streetName?: pulumi.Input<string>;
    /**
     * Street number of the address.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    streetNumber?: pulumi.Input<string>;
}
