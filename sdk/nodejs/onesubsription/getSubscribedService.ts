// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import { input as inputs, output as outputs } from "../types";
import * as utilities from "../utilities";

/**
 * This data source provides details about a specific Subscribed Service resource in Oracle Cloud Infrastructure Onesubscription service.
 *
 * This API returns the subscribed service details corresponding to the id provided
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testSubscribedService = oci.OneSubsription.getSubscribedService({
 *     subscribedServiceId: oci_onesubscription_subscribed_service.test_subscribed_service.id,
 *     fields: _var.subscribed_service_fields,
 * });
 * ```
 */
export function getSubscribedService(args: GetSubscribedServiceArgs, opts?: pulumi.InvokeOptions): Promise<GetSubscribedServiceResult> {
    if (!opts) {
        opts = {}
    }

    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
    return pulumi.runtime.invoke("oci:OneSubsription/getSubscribedService:getSubscribedService", {
        "fields": args.fields,
        "subscribedServiceId": args.subscribedServiceId,
    }, opts);
}

/**
 * A collection of arguments for invoking getSubscribedService.
 */
export interface GetSubscribedServiceArgs {
    /**
     * Partial response refers to an optimization technique offered by the RESTful web APIs to return only the information  (fields) required by the client. In this mechanism, the client sends the required field names as the query parameters for an API to the server, and the server trims down the default response content by removing the fields that are not required by the client. The parameter used to control what fields to return should be a query string parameter called "fields" of type array, and usecollectionFormat
     */
    fields?: string[];
    /**
     * The Subscribed Service Id
     */
    subscribedServiceId: string;
}

/**
 * A collection of values returned by getSubscribedService.
 */
export interface GetSubscribedServiceResult {
    /**
     * Subscribed service admin email id
     */
    readonly adminEmail: string;
    /**
     * Subscribed service agreement ID
     */
    readonly agreementId: string;
    /**
     * Subscribed service agrrement name
     */
    readonly agreementName: string;
    /**
     * Subscribed service agrrement type
     */
    readonly agreementType: string;
    /**
     * Commitment available amount
     */
    readonly availableAmount: string;
    /**
     * Address.
     */
    readonly billToAddresses: outputs.OneSubsription.GetSubscribedServiceBillToAddress[];
    /**
     * User.
     */
    readonly billToContacts: outputs.OneSubsription.GetSubscribedServiceBillToContact[];
    /**
     * Business partner.
     */
    readonly billToCustomers: outputs.OneSubsription.GetSubscribedServiceBillToCustomer[];
    /**
     * Subscribed service invoice frequency
     */
    readonly billingFrequency: string;
    /**
     * Booking Opportunity Number of Subscribed Service
     */
    readonly bookingOptyNumber: string;
    /**
     * Subscribed service buyer email id
     */
    readonly buyerEmail: string;
    /**
     * Subscribed service commitment schedule Id
     */
    readonly commitmentScheduleId: string;
    /**
     * List of Commitment services of a line
     */
    readonly commitmentServices: outputs.OneSubsription.GetSubscribedServiceCommitmentService[];
    /**
     * User that created the Payment term
     */
    readonly createdBy: string;
    /**
     * Subscribed service credit percentage
     */
    readonly creditPercentage: string;
    /**
     * Subscribed service CSI number
     */
    readonly csi: string;
    /**
     * Identifier for a customer's transactions for purchase of ay oracle services
     */
    readonly customerTransactionReference: string;
    /**
     * Subscribed service data center
     */
    readonly dataCenter: string;
    /**
     * Subscribed service data center region
     */
    readonly dataCenterRegion: string;
    /**
     * Subscribed service eligible to renew field
     */
    readonly eligibleToRenew: string;
    /**
     * Address.
     */
    readonly endUserAddresses: outputs.OneSubsription.GetSubscribedServiceEndUserAddress[];
    /**
     * User.
     */
    readonly endUserContacts: outputs.OneSubsription.GetSubscribedServiceEndUserContact[];
    /**
     * Business partner.
     */
    readonly endUserCustomers: outputs.OneSubsription.GetSubscribedServiceEndUserCustomer[];
    readonly fields?: string[];
    /**
     * Subscribed service fulfillment set
     */
    readonly fulfillmentSet: string;
    /**
     * Funded Allocation line value example: 12000.00
     */
    readonly fundedAllocationValue: string;
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * Indicates if a service can recieve usages and consequently have available amounts computed
     */
    readonly isAllowance: boolean;
    /**
     * If true compares rate between ratecard and the active pricelist and minimum rate would be fetched
     */
    readonly isCapToPriceList: boolean;
    /**
     * Used in context of service credit lines
     */
    readonly isCreditEnabled: boolean;
    /**
     * Indicator on whether or not there has been usage for the subscribed service
     */
    readonly isHavingUsage: boolean;
    /**
     * Subscribed service intent to pay flag
     */
    readonly isIntentToPay: boolean;
    /**
     * Subscribed service payg flag
     */
    readonly isPayg: boolean;
    /**
     * Indicates if the Subscribed service has a single ratecard
     */
    readonly isSingleRateCard: boolean;
    /**
     * Indicates if the commitment lines can have different quantities
     */
    readonly isVariableCommitment: boolean;
    /**
     * Subscribed service line net amount
     */
    readonly lineNetAmount: string;
    /**
     * Subscribed service Major Set
     */
    readonly majorSet: string;
    /**
     * Rate card tier net unit price
     */
    readonly netUnitPrice: string;
    /**
     * Subscribed service operation type
     */
    readonly operationType: string;
    /**
     * Sales Order Header associated to the subscribed service
     */
    readonly orderHeaderId: string;
    /**
     * Sales Order Line Id associated to the subscribed service
     */
    readonly orderLineId: string;
    /**
     * Sales Order Line Number associated to the subscribed service
     */
    readonly orderLineNumber: number;
    /**
     * Sales Order Number associated to the subscribed service
     */
    readonly orderNumber: string;
    /**
     * Order Type of Subscribed Service
     */
    readonly orderType: string;
    /**
     * Subscribed service Promotion Amount
     */
    readonly originalPromoAmount: string;
    /**
     * Overage Bill To of Subscribed Service
     */
    readonly overageBillTo: string;
    /**
     * Subscribed service Overage Discount Percentage
     */
    readonly overageDiscountPercentage: string;
    /**
     * Overage Policy of Subscribed Service
     */
    readonly overagePolicy: string;
    /**
     * Subscribed service partner credit amount
     */
    readonly partnerCreditAmount: string;
    /**
     * This field contains the name of the partner to which the subscription belongs - depending on which the invoicing may differ
     */
    readonly partnerTransactionType: string;
    /**
     * Pay As You Go policy of Subscribed Service (Can be null - indicating no payg policy)
     */
    readonly paygPolicy: string;
    /**
     * Payment Method of Subscribed Service
     */
    readonly paymentMethod: string;
    /**
     * Payment Number of Subscribed Service
     */
    readonly paymentNumber: string;
    /**
     * Payment Term details
     */
    readonly paymentTerms: outputs.OneSubsription.GetSubscribedServicePaymentTerm[];
    /**
     * Indicates the period for which the commitment amount can be utilised exceeding which the amount lapses. Also used in calculation of total contract line value
     */
    readonly pricePeriod: string;
    /**
     * Subscribed service pricing model
     */
    readonly pricingModel: string;
    /**
     * Product description
     */
    readonly products: outputs.OneSubsription.GetSubscribedServiceProduct[];
    /**
     * Subscribed service program type
     */
    readonly programType: string;
    /**
     * Not null if this service has an associated promotion line in SPM. Contains the line identifier from Order Management of  the associated promo line.
     */
    readonly promoOrderLineId: string;
    /**
     * Subscribed service promotion type
     */
    readonly promoType: string;
    /**
     * Promotion Pricing Type of Subscribed Service (Can be null - indicating no promotion pricing)
     */
    readonly promotionPricingType: string;
    /**
     * Subscribed service provisioning source
     */
    readonly provisioningSource: string;
    /**
     * Subscribed service quantity
     */
    readonly quantity: string;
    /**
     * Subscribed service Rate Card Discount Percentage
     */
    readonly rateCardDiscountPercentage: string;
    /**
     * List of Rate Cards of a Subscribed Service
     */
    readonly rateCards: outputs.OneSubsription.GetSubscribedServiceRateCard[];
    /**
     * SPM Ratecard Type
     */
    readonly ratecardType: string;
    /**
     * Subscribed service Opportunity Id
     */
    readonly renewalOptyId: string;
    /**
     * Renewal Opportunity Number of Subscribed Service
     */
    readonly renewalOptyNumber: string;
    /**
     * Renewal Opportunity Type of Subscribed Service
     */
    readonly renewalOptyType: string;
    /**
     * SPM renewed Subscription ID
     */
    readonly renewedSubscribedServiceId: string;
    /**
     * Address.
     */
    readonly resellerAddresses: outputs.OneSubsription.GetSubscribedServiceResellerAddress[];
    /**
     * User.
     */
    readonly resellerContacts: outputs.OneSubsription.GetSubscribedServiceResellerContact[];
    /**
     * Business partner.
     */
    readonly resellerCustomers: outputs.OneSubsription.GetSubscribedServiceResellerCustomer[];
    /**
     * Subscribed service Revenue Line Id
     */
    readonly revenueLineId: string;
    /**
     * Revenue Line NUmber of Subscribed Service
     */
    readonly revenueLineNumber: string;
    /**
     * Subscribed service Revised ARR
     */
    readonly revisedArrInLc: string;
    /**
     * Subscribed service Revised ARR in Standard Currency
     */
    readonly revisedArrInSc: string;
    /**
     * Subscribed service sales account party id
     */
    readonly salesAccountPartyId: string;
    /**
     * Sales Channel of Subscribed Service
     */
    readonly salesChannel: string;
    /**
     * Subscribed service line number
     */
    readonly serialNumber: string;
    /**
     * Address.
     */
    readonly serviceToAddresses: outputs.OneSubsription.GetSubscribedServiceServiceToAddress[];
    /**
     * User.
     */
    readonly serviceToContacts: outputs.OneSubsription.GetSubscribedServiceServiceToContact[];
    /**
     * Business partner.
     */
    readonly serviceToCustomers: outputs.OneSubsription.GetSubscribedServiceServiceToCustomer[];
    /**
     * User.
     */
    readonly soldToContacts: outputs.OneSubsription.GetSubscribedServiceSoldToContact[];
    /**
     * Business partner.
     */
    readonly soldToCustomers: outputs.OneSubsription.GetSubscribedServiceSoldToCustomer[];
    /**
     * Subscribed service start date type
     */
    readonly startDateType: string;
    /**
     * Subscribed service status
     */
    readonly status: string;
    /**
     * SPM internal Subscribed Service ID
     */
    readonly subscribedServiceId: string;
    /**
     * Subscription ID associated to the subscribed service
     */
    readonly subscriptionId: string;
    /**
     * Subscribed service source
     */
    readonly subscriptionSource: string;
    /**
     * Subscribed service System ARR
     */
    readonly systemArrInLc: string;
    /**
     * Subscribed service System ARR in Standard Currency
     */
    readonly systemArrInSc: string;
    /**
     * Subscribed service System ATR-ARR
     */
    readonly systemAtrArrInLc: string;
    /**
     * Subscribed service System ATR-ARR in Standard Currency
     */
    readonly systemAtrArrInSc: string;
    /**
     * Term value in Months
     */
    readonly termValue: string;
    /**
     * Term value UOM
     */
    readonly termValueUom: string;
    /**
     * Subscribed service agrrement end date
     */
    readonly timeAgreementEnd: string;
    /**
     * Subscribed service creation date
     */
    readonly timeCreated: string;
    /**
     * Subscribed service customer config date
     */
    readonly timeCustomerConfig: string;
    /**
     * Subscribed service end date
     */
    readonly timeEnd: string;
    /**
     * Subscribed service Major Set End date
     */
    readonly timeMajorsetEnd: string;
    /**
     * Subscribed service Major Set Start date
     */
    readonly timeMajorsetStart: string;
    /**
     * Subscribed service payment expiry date
     */
    readonly timePaymentExpiry: string;
    /**
     * Subscribed service provisioning date
     */
    readonly timeProvisioned: string;
    /**
     * Subscribed service service configuration email sent date
     */
    readonly timeServiceConfigurationEmailSent: string;
    /**
     * Subscribed service start date
     */
    readonly timeStart: string;
    /**
     * Subscribed service last update date
     */
    readonly timeUpdated: string;
    /**
     * Subscribed service welcome email sent date
     */
    readonly timeWelcomeEmailSent: string;
    /**
     * Subscribed service total value
     */
    readonly totalValue: string;
    /**
     * Subscribed service Transaction Extension Id
     */
    readonly transactionExtensionId: string;
    /**
     * Subscribed Service line type
     */
    readonly type: string;
    /**
     * User that updated the subscribed service
     */
    readonly updatedBy: string;
    /**
     * Subscribed service used amount
     */
    readonly usedAmount: string;
}

export function getSubscribedServiceOutput(args: GetSubscribedServiceOutputArgs, opts?: pulumi.InvokeOptions): pulumi.Output<GetSubscribedServiceResult> {
    return pulumi.output(args).apply(a => getSubscribedService(a, opts))
}

/**
 * A collection of arguments for invoking getSubscribedService.
 */
export interface GetSubscribedServiceOutputArgs {
    /**
     * Partial response refers to an optimization technique offered by the RESTful web APIs to return only the information  (fields) required by the client. In this mechanism, the client sends the required field names as the query parameters for an API to the server, and the server trims down the default response content by removing the fields that are not required by the client. The parameter used to control what fields to return should be a query string parameter called "fields" of type array, and usecollectionFormat
     */
    fields?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The Subscribed Service Id
     */
    subscribedServiceId: pulumi.Input<string>;
}