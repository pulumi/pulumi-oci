// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Address resource in Oracle Cloud Infrastructure Osp Gateway service.
 *
 * Get the address by id for the compartment
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAddress = oci.OspGateway.getAddress({
 *     addressId: testAddres.id,
 *     compartmentId: compartmentId,
 *     ospHomeRegion: addressOspHomeRegion,
 * });
 * ```
 */
export function getAddress(args: GetAddressArgs, opts?: pulumi.InvokeOptions): Promise<GetAddressResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:OspGateway/getAddress:getAddress", {
        "addressId": args.addressId,
        "compartmentId": args.compartmentId,
        "ospHomeRegion": args.ospHomeRegion,
    }, opts);
}

/**
 * A collection of arguments for invoking getAddress.
 */
export interface GetAddressArgs {
    /**
     * The identifier of the address.
     */
    addressId: string;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: string;
    /**
     * The home region's public name of the logged in user.
     */
    ospHomeRegion: string;
}

/**
 * A collection of values returned by getAddress.
 */
export interface GetAddressResult {
    readonly addressId: string;
    /**
     * Address identifier.
     */
    readonly addressKey: string;
    /**
     * Name of the city.
     */
    readonly city: string;
    /**
     * Name of the customer company.
     */
    readonly companyName: string;
    readonly compartmentId: string;
    /**
     * Contributor class of the customer company.
     */
    readonly contributorClass: string;
    /**
     * Country of the address.
     */
    readonly country: string;
    /**
     * County of the address.
     */
    readonly county: string;
    /**
     * Department name of the customer company.
     */
    readonly departmentName: string;
    /**
     * Contact person email address.
     */
    readonly emailAddress: string;
    /**
     * First name of the contact person.
     */
    readonly firstName: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Internal number of the customer company.
     */
    readonly internalNumber: string;
    /**
     * Job title of the contact person.
     */
    readonly jobTitle: string;
    /**
     * Last name of the contact person.
     */
    readonly lastName: string;
    /**
     * Address line 1.
     */
    readonly line1: string;
    /**
     * Address line 2.
     */
    readonly line2: string;
    /**
     * Address line 3.
     */
    readonly line3: string;
    /**
     * Address line 4.
     */
    readonly line4: string;
    /**
     * Middle name of the contact person.
     */
    readonly middleName: string;
    /**
     * Municipal Inscription.
     */
    readonly municipalInscription: string;
    readonly ospHomeRegion: string;
    /**
     * Phone country code of the contact person.
     */
    readonly phoneCountryCode: string;
    /**
     * Phone number of the contact person.
     */
    readonly phoneNumber: string;
    /**
     * Post code of the address.
     */
    readonly postalCode: string;
    /**
     * Province of the address.
     */
    readonly province: string;
    /**
     * State of the address.
     */
    readonly state: string;
    /**
     * State Inscription.
     */
    readonly stateInscription: string;
    /**
     * Street name of the address.
     */
    readonly streetName: string;
    /**
     * Street number of the address.
     */
    readonly streetNumber: string;
}
/**
 * This data source provides details about a specific Address resource in Oracle Cloud Infrastructure Osp Gateway service.
 *
 * Get the address by id for the compartment
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testAddress = oci.OspGateway.getAddress({
 *     addressId: testAddres.id,
 *     compartmentId: compartmentId,
 *     ospHomeRegion: addressOspHomeRegion,
 * });
 * ```
 */
export function getAddressOutput(args: GetAddressOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetAddressResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:OspGateway/getAddress:getAddress", {
        "addressId": args.addressId,
        "compartmentId": args.compartmentId,
        "ospHomeRegion": args.ospHomeRegion,
    }, opts);
}

/**
 * A collection of arguments for invoking getAddress.
 */
export interface GetAddressOutputArgs {
    /**
     * The identifier of the address.
     */
    addressId: pulumi.Input<string>;
    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * The home region's public name of the logged in user.
     */
    ospHomeRegion: pulumi.Input<string>;
}
