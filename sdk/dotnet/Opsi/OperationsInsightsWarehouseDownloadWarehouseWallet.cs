// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi
{
    /// <summary>
    /// This resource provides the Operations Insights Warehouse Download Warehouse Wallet resource in Oracle Cloud Infrastructure Opsi service.
    /// 
    /// Download the ADW wallet for Operations Insights Warehouse using which the Hub data is exposed.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using System.Collections.Generic;
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// return await Deployment.RunAsync(() =&gt; 
    /// {
    ///     var testOperationsInsightsWarehouseDownloadWarehouseWallet = new Oci.Opsi.OperationsInsightsWarehouseDownloadWarehouseWallet("testOperationsInsightsWarehouseDownloadWarehouseWallet", new()
    ///     {
    ///         OperationsInsightsWarehouseId = oci_opsi_operations_insights_warehouse.Test_operations_insights_warehouse.Id,
    ///         OperationsInsightsWarehouseWalletPassword = @var.Operations_insights_warehouse_download_warehouse_wallet_operations_insights_warehouse_wallet_password,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// OperationsInsightsWarehouseDownloadWarehouseWallet can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:Opsi/operationsInsightsWarehouseDownloadWarehouseWallet:OperationsInsightsWarehouseDownloadWarehouseWallet test_operations_insights_warehouse_download_warehouse_wallet "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Opsi/operationsInsightsWarehouseDownloadWarehouseWallet:OperationsInsightsWarehouseDownloadWarehouseWallet")]
    public partial class OperationsInsightsWarehouseDownloadWarehouseWallet : global::Pulumi.CustomResource
    {
        /// <summary>
        /// Unique Operations Insights Warehouse identifier
        /// </summary>
        [Output("operationsInsightsWarehouseId")]
        public Output<string> OperationsInsightsWarehouseId { get; private set; } = null!;

        /// <summary>
        /// User provided ADW wallet password for the Operations Insights Warehouse.
        /// </summary>
        [Output("operationsInsightsWarehouseWalletPassword")]
        public Output<string> OperationsInsightsWarehouseWalletPassword { get; private set; } = null!;


        /// <summary>
        /// Create a OperationsInsightsWarehouseDownloadWarehouseWallet resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public OperationsInsightsWarehouseDownloadWarehouseWallet(string name, OperationsInsightsWarehouseDownloadWarehouseWalletArgs args, CustomResourceOptions? options = null)
            : base("oci:Opsi/operationsInsightsWarehouseDownloadWarehouseWallet:OperationsInsightsWarehouseDownloadWarehouseWallet", name, args ?? new OperationsInsightsWarehouseDownloadWarehouseWalletArgs(), MakeResourceOptions(options, ""))
        {
        }

        private OperationsInsightsWarehouseDownloadWarehouseWallet(string name, Input<string> id, OperationsInsightsWarehouseDownloadWarehouseWalletState? state = null, CustomResourceOptions? options = null)
            : base("oci:Opsi/operationsInsightsWarehouseDownloadWarehouseWallet:OperationsInsightsWarehouseDownloadWarehouseWallet", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing OperationsInsightsWarehouseDownloadWarehouseWallet resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static OperationsInsightsWarehouseDownloadWarehouseWallet Get(string name, Input<string> id, OperationsInsightsWarehouseDownloadWarehouseWalletState? state = null, CustomResourceOptions? options = null)
        {
            return new OperationsInsightsWarehouseDownloadWarehouseWallet(name, id, state, options);
        }
    }

    public sealed class OperationsInsightsWarehouseDownloadWarehouseWalletArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Unique Operations Insights Warehouse identifier
        /// </summary>
        [Input("operationsInsightsWarehouseId", required: true)]
        public Input<string> OperationsInsightsWarehouseId { get; set; } = null!;

        /// <summary>
        /// User provided ADW wallet password for the Operations Insights Warehouse.
        /// </summary>
        [Input("operationsInsightsWarehouseWalletPassword", required: true)]
        public Input<string> OperationsInsightsWarehouseWalletPassword { get; set; } = null!;

        public OperationsInsightsWarehouseDownloadWarehouseWalletArgs()
        {
        }
        public static new OperationsInsightsWarehouseDownloadWarehouseWalletArgs Empty => new OperationsInsightsWarehouseDownloadWarehouseWalletArgs();
    }

    public sealed class OperationsInsightsWarehouseDownloadWarehouseWalletState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Unique Operations Insights Warehouse identifier
        /// </summary>
        [Input("operationsInsightsWarehouseId")]
        public Input<string>? OperationsInsightsWarehouseId { get; set; }

        /// <summary>
        /// User provided ADW wallet password for the Operations Insights Warehouse.
        /// </summary>
        [Input("operationsInsightsWarehouseWalletPassword")]
        public Input<string>? OperationsInsightsWarehouseWalletPassword { get; set; }

        public OperationsInsightsWarehouseDownloadWarehouseWalletState()
        {
        }
        public static new OperationsInsightsWarehouseDownloadWarehouseWalletState Empty => new OperationsInsightsWarehouseDownloadWarehouseWalletState();
    }
}