// *** WARNING: this file was generated by pulumi-language-nodejs. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "../utilities";

/**
 * This resource provides the Operations Insights Warehouse Download Warehouse Wallet resource in Oracle Cloud Infrastructure Opsi service.
 *
 * Download the ADW wallet for Operations Insights Warehouse using which the Hub data is exposed.
 *
 * ## Example Usage
 *
 * ```typescript
 * import * as pulumi from "@pulumi/pulumi";
 * import * as oci from "@pulumi/oci";
 *
 * const testOperationsInsightsWarehouseDownloadWarehouseWallet = new oci.opsi.OperationsInsightsWarehouseDownloadWarehouseWallet("test_operations_insights_warehouse_download_warehouse_wallet", {
 *     operationsInsightsWarehouseId: testOperationsInsightsWarehouse.id,
 *     operationsInsightsWarehouseWalletPassword: operationsInsightsWarehouseDownloadWarehouseWalletOperationsInsightsWarehouseWalletPassword,
 * });
 * ```
 *
 * ## Import
 *
 * OperationsInsightsWarehouseDownloadWarehouseWallet can be imported using the `id`, e.g.
 *
 * ```sh
 * $ pulumi import oci:Opsi/operationsInsightsWarehouseDownloadWarehouseWallet:OperationsInsightsWarehouseDownloadWarehouseWallet test_operations_insights_warehouse_download_warehouse_wallet "id"
 * ```
 */
export class OperationsInsightsWarehouseDownloadWarehouseWallet extends pulumi.CustomResource {
    /**
     * Get an existing OperationsInsightsWarehouseDownloadWarehouseWallet resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: OperationsInsightsWarehouseDownloadWarehouseWalletState, opts?: pulumi.CustomResourceOptions): OperationsInsightsWarehouseDownloadWarehouseWallet {
        return new OperationsInsightsWarehouseDownloadWarehouseWallet(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'oci:Opsi/operationsInsightsWarehouseDownloadWarehouseWallet:OperationsInsightsWarehouseDownloadWarehouseWallet';

    /**
     * Returns true if the given object is an instance of OperationsInsightsWarehouseDownloadWarehouseWallet.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is OperationsInsightsWarehouseDownloadWarehouseWallet {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === OperationsInsightsWarehouseDownloadWarehouseWallet.__pulumiType;
    }

    /**
     * Unique Ops Insights Warehouse identifier
     */
    public readonly operationsInsightsWarehouseId!: pulumi.Output<string>;
    /**
     * User provided ADW wallet password for the Ops Insights Warehouse.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    public readonly operationsInsightsWarehouseWalletPassword!: pulumi.Output<string>;

    /**
     * Create a OperationsInsightsWarehouseDownloadWarehouseWallet resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: OperationsInsightsWarehouseDownloadWarehouseWalletArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: OperationsInsightsWarehouseDownloadWarehouseWalletArgs | OperationsInsightsWarehouseDownloadWarehouseWalletState, opts?: pulumi.CustomResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (opts.id) {
            const state = argsOrState as OperationsInsightsWarehouseDownloadWarehouseWalletState | undefined;
            resourceInputs["operationsInsightsWarehouseId"] = state ? state.operationsInsightsWarehouseId : undefined;
            resourceInputs["operationsInsightsWarehouseWalletPassword"] = state ? state.operationsInsightsWarehouseWalletPassword : undefined;
        } else {
            const args = argsOrState as OperationsInsightsWarehouseDownloadWarehouseWalletArgs | undefined;
            if ((!args || args.operationsInsightsWarehouseId === undefined) && !opts.urn) {
                throw new Error("Missing required property 'operationsInsightsWarehouseId'");
            }
            if ((!args || args.operationsInsightsWarehouseWalletPassword === undefined) && !opts.urn) {
                throw new Error("Missing required property 'operationsInsightsWarehouseWalletPassword'");
            }
            resourceInputs["operationsInsightsWarehouseId"] = args ? args.operationsInsightsWarehouseId : undefined;
            resourceInputs["operationsInsightsWarehouseWalletPassword"] = args?.operationsInsightsWarehouseWalletPassword ? pulumi.secret(args.operationsInsightsWarehouseWalletPassword) : undefined;
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        const secretOpts = { additionalSecretOutputs: ["operationsInsightsWarehouseWalletPassword"] };
        opts = pulumi.mergeOptions(opts, secretOpts);
        super(OperationsInsightsWarehouseDownloadWarehouseWallet.__pulumiType, name, resourceInputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering OperationsInsightsWarehouseDownloadWarehouseWallet resources.
 */
export interface OperationsInsightsWarehouseDownloadWarehouseWalletState {
    /**
     * Unique Ops Insights Warehouse identifier
     */
    operationsInsightsWarehouseId?: pulumi.Input<string>;
    /**
     * User provided ADW wallet password for the Ops Insights Warehouse.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    operationsInsightsWarehouseWalletPassword?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a OperationsInsightsWarehouseDownloadWarehouseWallet resource.
 */
export interface OperationsInsightsWarehouseDownloadWarehouseWalletArgs {
    /**
     * Unique Ops Insights Warehouse identifier
     */
    operationsInsightsWarehouseId: pulumi.Input<string>;
    /**
     * User provided ADW wallet password for the Ops Insights Warehouse.
     *
     *
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     */
    operationsInsightsWarehouseWalletPassword: pulumi.Input<string>;
}
