// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi
{
    public static class GetOperationsInsightsWarehouses
    {
        /// <summary>
        /// This data source provides the list of Operations Insights Warehouses in Oracle Cloud Infrastructure Opsi service.
        /// 
        /// Gets a list of Operations Insights warehouses. Either compartmentId or id must be specified. 
        /// There is only expected to be 1 warehouse per tenant. The warehouse is expected to be in the root compartment.
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
        ///     var testOperationsInsightsWarehouses = Oci.Opsi.GetOperationsInsightsWarehouses.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Operations_insights_warehouse_display_name,
        ///         Id = @var.Operations_insights_warehouse_id,
        ///         States = @var.Operations_insights_warehouse_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetOperationsInsightsWarehousesResult> InvokeAsync(GetOperationsInsightsWarehousesArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetOperationsInsightsWarehousesResult>("oci:Opsi/getOperationsInsightsWarehouses:getOperationsInsightsWarehouses", args ?? new GetOperationsInsightsWarehousesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Operations Insights Warehouses in Oracle Cloud Infrastructure Opsi service.
        /// 
        /// Gets a list of Operations Insights warehouses. Either compartmentId or id must be specified. 
        /// There is only expected to be 1 warehouse per tenant. The warehouse is expected to be in the root compartment.
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
        ///     var testOperationsInsightsWarehouses = Oci.Opsi.GetOperationsInsightsWarehouses.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         DisplayName = @var.Operations_insights_warehouse_display_name,
        ///         Id = @var.Operations_insights_warehouse_id,
        ///         States = @var.Operations_insights_warehouse_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetOperationsInsightsWarehousesResult> Invoke(GetOperationsInsightsWarehousesInvokeArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetOperationsInsightsWarehousesResult>("oci:Opsi/getOperationsInsightsWarehouses:getOperationsInsightsWarehouses", args ?? new GetOperationsInsightsWarehousesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetOperationsInsightsWarehousesArgs : global::Pulumi.InvokeArgs
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
        private List<Inputs.GetOperationsInsightsWarehousesFilterArgs>? _filters;
        public List<Inputs.GetOperationsInsightsWarehousesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetOperationsInsightsWarehousesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique Operations Insights Warehouse identifier
        /// </summary>
        [Input("id")]
        public string? Id { get; set; }

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

        public GetOperationsInsightsWarehousesArgs()
        {
        }
        public static new GetOperationsInsightsWarehousesArgs Empty => new GetOperationsInsightsWarehousesArgs();
    }

    public sealed class GetOperationsInsightsWarehousesInvokeArgs : global::Pulumi.InvokeArgs
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
        private InputList<Inputs.GetOperationsInsightsWarehousesFilterInputArgs>? _filters;
        public InputList<Inputs.GetOperationsInsightsWarehousesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetOperationsInsightsWarehousesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique Operations Insights Warehouse identifier
        /// </summary>
        [Input("id")]
        public Input<string>? Id { get; set; }

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

        public GetOperationsInsightsWarehousesInvokeArgs()
        {
        }
        public static new GetOperationsInsightsWarehousesInvokeArgs Empty => new GetOperationsInsightsWarehousesInvokeArgs();
    }


    [OutputType]
    public sealed class GetOperationsInsightsWarehousesResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// User-friedly name of Operations Insights Warehouse that does not have to be unique.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetOperationsInsightsWarehousesFilterResult> Filters;
        /// <summary>
        /// OPSI Warehouse OCID
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The list of operations_insights_warehouse_summary_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOperationsInsightsWarehousesOperationsInsightsWarehouseSummaryCollectionResult> OperationsInsightsWarehouseSummaryCollections;
        /// <summary>
        /// Possible lifecycle states
        /// </summary>
        public readonly ImmutableArray<string> States;

        [OutputConstructor]
        private GetOperationsInsightsWarehousesResult(
            string? compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetOperationsInsightsWarehousesFilterResult> filters,

            string? id,

            ImmutableArray<Outputs.GetOperationsInsightsWarehousesOperationsInsightsWarehouseSummaryCollectionResult> operationsInsightsWarehouseSummaryCollections,

            ImmutableArray<string> states)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            OperationsInsightsWarehouseSummaryCollections = operationsInsightsWarehouseSummaryCollections;
            States = states;
        }
    }
}