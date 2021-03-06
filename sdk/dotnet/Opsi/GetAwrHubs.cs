// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi
{
    public static class GetAwrHubs
    {
        /// <summary>
        /// This data source provides the list of Awr Hubs in Oracle Cloud Infrastructure Opsi service.
        /// 
        /// Gets a list of AWR hubs. Either compartmentId or id must be specified. All these resources are expected to be in root compartment. 
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testAwrHubs = Output.Create(Oci.Opsi.GetAwrHubs.InvokeAsync(new Oci.Opsi.GetAwrHubsArgs
        ///         {
        ///             OperationsInsightsWarehouseId = oci_opsi_operations_insights_warehouse.Test_operations_insights_warehouse.Id,
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Awr_hub_display_name,
        ///             Id = @var.Awr_hub_id,
        ///             States = @var.Awr_hub_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAwrHubsResult> InvokeAsync(GetAwrHubsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetAwrHubsResult>("oci:Opsi/getAwrHubs:getAwrHubs", args ?? new GetAwrHubsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Awr Hubs in Oracle Cloud Infrastructure Opsi service.
        /// 
        /// Gets a list of AWR hubs. Either compartmentId or id must be specified. All these resources are expected to be in root compartment. 
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testAwrHubs = Output.Create(Oci.Opsi.GetAwrHubs.InvokeAsync(new Oci.Opsi.GetAwrHubsArgs
        ///         {
        ///             OperationsInsightsWarehouseId = oci_opsi_operations_insights_warehouse.Test_operations_insights_warehouse.Id,
        ///             CompartmentId = @var.Compartment_id,
        ///             DisplayName = @var.Awr_hub_display_name,
        ///             Id = @var.Awr_hub_id,
        ///             States = @var.Awr_hub_state,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetAwrHubsResult> Invoke(GetAwrHubsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetAwrHubsResult>("oci:Opsi/getAwrHubs:getAwrHubs", args ?? new GetAwrHubsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAwrHubsArgs : Pulumi.InvokeArgs
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
        private List<Inputs.GetAwrHubsFilterArgs>? _filters;
        public List<Inputs.GetAwrHubsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAwrHubsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique Awr Hub identifier
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

        public GetAwrHubsArgs()
        {
        }
    }

    public sealed class GetAwrHubsInvokeArgs : Pulumi.InvokeArgs
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
        private InputList<Inputs.GetAwrHubsFilterInputArgs>? _filters;
        public InputList<Inputs.GetAwrHubsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetAwrHubsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique Awr Hub identifier
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

        public GetAwrHubsInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetAwrHubsResult
    {
        /// <summary>
        /// The list of awr_hub_summary_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAwrHubsAwrHubSummaryCollectionResult> AwrHubSummaryCollections;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// User-friedly name of AWR Hub that does not have to be unique.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetAwrHubsFilterResult> Filters;
        /// <summary>
        /// AWR Hub OCID
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// OPSI Warehouse OCID
        /// </summary>
        public readonly string OperationsInsightsWarehouseId;
        /// <summary>
        /// Possible lifecycle states
        /// </summary>
        public readonly ImmutableArray<string> States;

        [OutputConstructor]
        private GetAwrHubsResult(
            ImmutableArray<Outputs.GetAwrHubsAwrHubSummaryCollectionResult> awrHubSummaryCollections,

            string? compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetAwrHubsFilterResult> filters,

            string? id,

            string operationsInsightsWarehouseId,

            ImmutableArray<string> states)
        {
            AwrHubSummaryCollections = awrHubSummaryCollections;
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            OperationsInsightsWarehouseId = operationsInsightsWarehouseId;
            States = states;
        }
    }
}
