// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi
{
    public static class GetOperationsInsightsWarehouseUsers
    {
        /// <summary>
        /// This data source provides the list of Operations Insights Warehouse Users in Oracle Cloud Infrastructure Opsi service.
        /// 
        /// Gets a list of Operations Insights Warehouse users. Either compartmentId or id must be specified. All these resources are expected to be in root compartment.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testOperationsInsightsWarehouseUsers = Oci.Opsi.GetOperationsInsightsWarehouseUsers.Invoke(new()
        ///     {
        ///         OperationsInsightsWarehouseId = oci_opsi_operations_insights_warehouse.Test_operations_insights_warehouse.Id,
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Operations_insights_warehouse_user_display_name,
        ///         Id = @var.Operations_insights_warehouse_user_id,
        ///         States = @var.Operations_insights_warehouse_user_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetOperationsInsightsWarehouseUsersResult> InvokeAsync(GetOperationsInsightsWarehouseUsersArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetOperationsInsightsWarehouseUsersResult>("oci:Opsi/getOperationsInsightsWarehouseUsers:getOperationsInsightsWarehouseUsers", args ?? new GetOperationsInsightsWarehouseUsersArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Operations Insights Warehouse Users in Oracle Cloud Infrastructure Opsi service.
        /// 
        /// Gets a list of Operations Insights Warehouse users. Either compartmentId or id must be specified. All these resources are expected to be in root compartment.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testOperationsInsightsWarehouseUsers = Oci.Opsi.GetOperationsInsightsWarehouseUsers.Invoke(new()
        ///     {
        ///         OperationsInsightsWarehouseId = oci_opsi_operations_insights_warehouse.Test_operations_insights_warehouse.Id,
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Operations_insights_warehouse_user_display_name,
        ///         Id = @var.Operations_insights_warehouse_user_id,
        ///         States = @var.Operations_insights_warehouse_user_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetOperationsInsightsWarehouseUsersResult> Invoke(GetOperationsInsightsWarehouseUsersInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetOperationsInsightsWarehouseUsersResult>("oci:Opsi/getOperationsInsightsWarehouseUsers:getOperationsInsightsWarehouseUsers", args ?? new GetOperationsInsightsWarehouseUsersInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetOperationsInsightsWarehouseUsersArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetOperationsInsightsWarehouseUsersFilterArgs>? _filters;
        public List<Inputs.GetOperationsInsightsWarehouseUsersFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetOperationsInsightsWarehouseUsersFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique Operations Insights Warehouse User identifier
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

        /// <summary>
        /// Unique Operations Insights Warehouse identifier
        /// </summary>
        [Input("operationsInsightsWarehouseId", required: true)]
        public string OperationsInsightsWarehouseId { get; set; } = null!;

        [Input("states")]
        private List<string>? _states;

        /// <summary>
        /// Lifecycle states
        /// </summary>
        public List<string> States
        {
            get => _states ?? (_states = new List<string>());
            set => _states = value;
        }

        public GetOperationsInsightsWarehouseUsersArgs()
        {
        }
        public static new GetOperationsInsightsWarehouseUsersArgs Empty => new GetOperationsInsightsWarehouseUsersArgs();
    }

    public sealed class GetOperationsInsightsWarehouseUsersInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetOperationsInsightsWarehouseUsersFilterInputArgs>? _filters;
        public InputList<Inputs.GetOperationsInsightsWarehouseUsersFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetOperationsInsightsWarehouseUsersFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique Operations Insights Warehouse User identifier
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

        /// <summary>
        /// Unique Operations Insights Warehouse identifier
        /// </summary>
        [Input("operationsInsightsWarehouseId", required: true)]
        public Input<string> OperationsInsightsWarehouseId { get; set; } = null!;

        [Input("states")]
        private InputList<string>? _states;

        /// <summary>
        /// Lifecycle states
        /// </summary>
        public InputList<string> States
        {
            get => _states ?? (_states = new InputList<string>());
            set => _states = value;
        }

        public GetOperationsInsightsWarehouseUsersInvokeArgs()
        {
        }
        public static new GetOperationsInsightsWarehouseUsersInvokeArgs Empty => new GetOperationsInsightsWarehouseUsersInvokeArgs();
    }


    [OutputType]
    public sealed class GetOperationsInsightsWarehouseUsersResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string? CompartmentId;
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetOperationsInsightsWarehouseUsersFilterResult> Filters;
        /// <summary>
        /// Hub User OCID
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// OPSI Warehouse OCID
        /// </summary>
        public readonly string OperationsInsightsWarehouseId;
        /// <summary>
        /// The list of operations_insights_warehouse_user_summary_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollectionResult> OperationsInsightsWarehouseUserSummaryCollections;
        /// <summary>
        /// Possible lifecycle states
        /// </summary>
        public readonly ImmutableArray<string> States;

        [OutputConstructor]
        private GetOperationsInsightsWarehouseUsersResult(
            string? compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetOperationsInsightsWarehouseUsersFilterResult> filters,

            string? id,

            string operationsInsightsWarehouseId,

            ImmutableArray<Outputs.GetOperationsInsightsWarehouseUsersOperationsInsightsWarehouseUserSummaryCollectionResult> operationsInsightsWarehouseUserSummaryCollections,

            ImmutableArray<string> states)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            OperationsInsightsWarehouseId = operationsInsightsWarehouseId;
            OperationsInsightsWarehouseUserSummaryCollections = operationsInsightsWarehouseUserSummaryCollections;
            States = states;
        }
    }
}