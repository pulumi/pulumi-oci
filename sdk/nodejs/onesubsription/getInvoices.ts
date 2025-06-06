// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "../types/input";
import * as outputs from "../types/output";
import * as utilities from "../utilities";

/**
 * This data source provides the list of Invoices in Oracle Cloud Infrastructure Onesubscription service.
 *
 * This is a collection API which returns a list of Invoices for given filters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInvoices = oci.OneSubsription.getInvoices({
 *     arCustomerTransactionId: testArCustomerTransaction.id,
 *     compartmentId: compartmentId,
 *     fields: invoiceFields,
 *     timeFrom: invoiceTimeFrom,
 *     timeTo: invoiceTimeTo,
 * });
 * ```
 */
export function getInvoices(args: GetInvoicesArgs, opts?: pulumi.InvokeOptions): Promise<GetInvoicesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invoke("oci:OneSubsription/getInvoices:getInvoices", {
        "arCustomerTransactionId": args.arCustomerTransactionId,
        "compartmentId": args.compartmentId,
        "fields": args.fields,
        "filters": args.filters,
        "timeFrom": args.timeFrom,
        "timeTo": args.timeTo,
    }, opts);
}

/**
 * A collection of arguments for invoking getInvoices.
 */
export interface GetInvoicesArgs {
    /**
     * AR Unique identifier for an invoice .
     */
    arCustomerTransactionId: string;
    /**
     * The OCID of the root compartment.
     */
    compartmentId: string;
    /**
     * Partial response refers to an optimization technique offered by the RESTful web APIs to return only the information  (fields) required by the client. This parameter is used to control what fields to return.
     */
    fields?: string[];
    filters?: inputs.OneSubsription.GetInvoicesFilter[];
    /**
     * Initial date to filter Invoice data in SPM.
     */
    timeFrom?: string;
    /**
     * Final date to filter Invoice data in SPM.
     */
    timeTo?: string;
}

/**
 * A collection of values returned by getInvoices.
 */
export interface GetInvoicesResult {
    readonly arCustomerTransactionId: string;
    readonly compartmentId: string;
    readonly fields?: string[];
    readonly filters?: outputs.OneSubsription.GetInvoicesFilter[];
    /**
     * The provider-assigned unique ID for this managed resource.
     */
    readonly id: string;
    /**
     * The list of invoices.
     */
    readonly invoices: outputs.OneSubsription.GetInvoicesInvoice[];
    readonly timeFrom?: string;
    readonly timeTo?: string;
}
/**
 * This data source provides the list of Invoices in Oracle Cloud Infrastructure Onesubscription service.
 *
 * This is a collection API which returns a list of Invoices for given filters.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testInvoices = oci.OneSubsription.getInvoices({
 *     arCustomerTransactionId: testArCustomerTransaction.id,
 *     compartmentId: compartmentId,
 *     fields: invoiceFields,
 *     timeFrom: invoiceTimeFrom,
 *     timeTo: invoiceTimeTo,
 * });
 * ```
 */
export function getInvoicesOutput(args: GetInvoicesOutputArgs, opts?: pulumi.InvokeOutputOptions): pulumi.Output<GetInvoicesResult> {
    opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts || {});
    return pulumi.runtime.invokeOutput("oci:OneSubsription/getInvoices:getInvoices", {
        "arCustomerTransactionId": args.arCustomerTransactionId,
        "compartmentId": args.compartmentId,
        "fields": args.fields,
        "filters": args.filters,
        "timeFrom": args.timeFrom,
        "timeTo": args.timeTo,
    }, opts);
}

/**
 * A collection of arguments for invoking getInvoices.
 */
export interface GetInvoicesOutputArgs {
    /**
     * AR Unique identifier for an invoice .
     */
    arCustomerTransactionId: pulumi.Input<string>;
    /**
     * The OCID of the root compartment.
     */
    compartmentId: pulumi.Input<string>;
    /**
     * Partial response refers to an optimization technique offered by the RESTful web APIs to return only the information  (fields) required by the client. This parameter is used to control what fields to return.
     */
    fields?: pulumi.Input<pulumi.Input<string>[]>;
    filters?: pulumi.Input<pulumi.Input<inputs.OneSubsription.GetInvoicesFilterArgs>[]>;
    /**
     * Initial date to filter Invoice data in SPM.
     */
    timeFrom?: pulumi.Input<string>;
    /**
     * Final date to filter Invoice data in SPM.
     */
    timeTo?: pulumi.Input<string>;
}
