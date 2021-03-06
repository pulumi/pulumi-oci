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
    /// This resource provides the Operations Insights Warehouse Rotate Warehouse Wallet resource in Oracle Cloud Infrastructure Opsi service.
    /// 
    /// Rotate the ADW wallet for Operations Insights Warehouse using which the Hub data is exposed.
    /// 
    /// ## Example Usage
    /// 
    /// ```csharp
    /// using Pulumi;
    /// using Oci = Pulumi.Oci;
    /// 
    /// class MyStack : Stack
    /// {
    ///     public MyStack()
    ///     {
    ///         var testOperationsInsightsWarehouseRotateWarehouseWallet = new Oci.Opsi.OperationsInsightsWarehouseRotateWarehouseWallet("testOperationsInsightsWarehouseRotateWarehouseWallet", new Oci.Opsi.OperationsInsightsWarehouseRotateWarehouseWalletArgs
    ///         {
    ///             OperationsInsightsWarehouseId = oci_opsi_operations_insights_warehouse.Test_operations_insights_warehouse.Id,
    ///         });
    ///     }
    /// 
    /// }
    /// ```
    /// 
    /// ## Import
    /// 
    /// OperationsInsightsWarehouseRotateWarehouseWallet can be imported using the `id`, e.g.
    /// 
    /// ```sh
    ///  $ pulumi import oci:Opsi/operationsInsightsWarehouseRotateWarehouseWallet:OperationsInsightsWarehouseRotateWarehouseWallet test_operations_insights_warehouse_rotate_warehouse_wallet "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:Opsi/operationsInsightsWarehouseRotateWarehouseWallet:OperationsInsightsWarehouseRotateWarehouseWallet")]
    public partial class OperationsInsightsWarehouseRotateWarehouseWallet : Pulumi.CustomResource
    {
        /// <summary>
        /// Unique Operations Insights Warehouse identifier
        /// </summary>
        [Output("operationsInsightsWarehouseId")]
        public Output<string> OperationsInsightsWarehouseId { get; private set; } = null!;


        /// <summary>
        /// Create a OperationsInsightsWarehouseRotateWarehouseWallet resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public OperationsInsightsWarehouseRotateWarehouseWallet(string name, OperationsInsightsWarehouseRotateWarehouseWalletArgs args, CustomResourceOptions? options = null)
            : base("oci:Opsi/operationsInsightsWarehouseRotateWarehouseWallet:OperationsInsightsWarehouseRotateWarehouseWallet", name, args ?? new OperationsInsightsWarehouseRotateWarehouseWalletArgs(), MakeResourceOptions(options, ""))
        {
        }

        private OperationsInsightsWarehouseRotateWarehouseWallet(string name, Input<string> id, OperationsInsightsWarehouseRotateWarehouseWalletState? state = null, CustomResourceOptions? options = null)
            : base("oci:Opsi/operationsInsightsWarehouseRotateWarehouseWallet:OperationsInsightsWarehouseRotateWarehouseWallet", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing OperationsInsightsWarehouseRotateWarehouseWallet resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static OperationsInsightsWarehouseRotateWarehouseWallet Get(string name, Input<string> id, OperationsInsightsWarehouseRotateWarehouseWalletState? state = null, CustomResourceOptions? options = null)
        {
            return new OperationsInsightsWarehouseRotateWarehouseWallet(name, id, state, options);
        }
    }

    public sealed class OperationsInsightsWarehouseRotateWarehouseWalletArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Unique Operations Insights Warehouse identifier
        /// </summary>
        [Input("operationsInsightsWarehouseId", required: true)]
        public Input<string> OperationsInsightsWarehouseId { get; set; } = null!;

        public OperationsInsightsWarehouseRotateWarehouseWalletArgs()
        {
        }
    }

    public sealed class OperationsInsightsWarehouseRotateWarehouseWalletState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Unique Operations Insights Warehouse identifier
        /// </summary>
        [Input("operationsInsightsWarehouseId")]
        public Input<string>? OperationsInsightsWarehouseId { get; set; }

        public OperationsInsightsWarehouseRotateWarehouseWalletState()
        {
        }
    }
}
