// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi
{
    public static class GetOperationsInsightsPrivateEndpoints
    {
        /// <summary>
        /// This data source provides the list of Operations Insights Private Endpoints in Oracle Cloud Infrastructure Opsi service.
        /// 
        /// Gets a list of Operation Insights private endpoints.
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
        ///     var testOperationsInsightsPrivateEndpoints = Oci.Opsi.GetOperationsInsightsPrivateEndpoints.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         CompartmentIdInSubtree = @var.Operations_insights_private_endpoint_compartment_id_in_subtree,
        ///         DisplayName = @var.Operations_insights_private_endpoint_display_name,
        ///         IsUsedForRacDbs = @var.Operations_insights_private_endpoint_is_used_for_rac_dbs,
        ///         OpsiPrivateEndpointId = oci_dataflow_private_endpoint.Test_private_endpoint.Id,
        ///         States = @var.Operations_insights_private_endpoint_state,
        ///         VcnId = oci_core_vcn.Test_vcn.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetOperationsInsightsPrivateEndpointsResult> InvokeAsync(GetOperationsInsightsPrivateEndpointsArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetOperationsInsightsPrivateEndpointsResult>("oci:Opsi/getOperationsInsightsPrivateEndpoints:getOperationsInsightsPrivateEndpoints", args ?? new GetOperationsInsightsPrivateEndpointsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Operations Insights Private Endpoints in Oracle Cloud Infrastructure Opsi service.
        /// 
        /// Gets a list of Operation Insights private endpoints.
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
        ///     var testOperationsInsightsPrivateEndpoints = Oci.Opsi.GetOperationsInsightsPrivateEndpoints.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         CompartmentIdInSubtree = @var.Operations_insights_private_endpoint_compartment_id_in_subtree,
        ///         DisplayName = @var.Operations_insights_private_endpoint_display_name,
        ///         IsUsedForRacDbs = @var.Operations_insights_private_endpoint_is_used_for_rac_dbs,
        ///         OpsiPrivateEndpointId = oci_dataflow_private_endpoint.Test_private_endpoint.Id,
        ///         States = @var.Operations_insights_private_endpoint_state,
        ///         VcnId = oci_core_vcn.Test_vcn.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetOperationsInsightsPrivateEndpointsResult> Invoke(GetOperationsInsightsPrivateEndpointsInvokeArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetOperationsInsightsPrivateEndpointsResult>("oci:Opsi/getOperationsInsightsPrivateEndpoints:getOperationsInsightsPrivateEndpoints", args ?? new GetOperationsInsightsPrivateEndpointsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetOperationsInsightsPrivateEndpointsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// A flag to search all resources within a given compartment and all sub-compartments.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public bool? CompartmentIdInSubtree { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetOperationsInsightsPrivateEndpointsFilterArgs>? _filters;
        public List<Inputs.GetOperationsInsightsPrivateEndpointsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetOperationsInsightsPrivateEndpointsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The option to filter OPSI private endpoints that can used for RAC. Should be used along with vcnId query parameter.
        /// </summary>
        [Input("isUsedForRacDbs")]
        public bool? IsUsedForRacDbs { get; set; }

        /// <summary>
        /// Unique Operations Insights PrivateEndpoint identifier
        /// </summary>
        [Input("opsiPrivateEndpointId")]
        public string? OpsiPrivateEndpointId { get; set; }

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

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
        /// </summary>
        [Input("vcnId")]
        public string? VcnId { get; set; }

        public GetOperationsInsightsPrivateEndpointsArgs()
        {
        }
        public static new GetOperationsInsightsPrivateEndpointsArgs Empty => new GetOperationsInsightsPrivateEndpointsArgs();
    }

    public sealed class GetOperationsInsightsPrivateEndpointsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// A flag to search all resources within a given compartment and all sub-compartments.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public Input<bool>? CompartmentIdInSubtree { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetOperationsInsightsPrivateEndpointsFilterInputArgs>? _filters;
        public InputList<Inputs.GetOperationsInsightsPrivateEndpointsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetOperationsInsightsPrivateEndpointsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The option to filter OPSI private endpoints that can used for RAC. Should be used along with vcnId query parameter.
        /// </summary>
        [Input("isUsedForRacDbs")]
        public Input<bool>? IsUsedForRacDbs { get; set; }

        /// <summary>
        /// Unique Operations Insights PrivateEndpoint identifier
        /// </summary>
        [Input("opsiPrivateEndpointId")]
        public Input<string>? OpsiPrivateEndpointId { get; set; }

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

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN.
        /// </summary>
        [Input("vcnId")]
        public Input<string>? VcnId { get; set; }

        public GetOperationsInsightsPrivateEndpointsInvokeArgs()
        {
        }
        public static new GetOperationsInsightsPrivateEndpointsInvokeArgs Empty => new GetOperationsInsightsPrivateEndpointsInvokeArgs();
    }


    [OutputType]
    public sealed class GetOperationsInsightsPrivateEndpointsResult
    {
        /// <summary>
        /// The compartment OCID of the Private service accessed database.
        /// </summary>
        public readonly string? CompartmentId;
        public readonly bool? CompartmentIdInSubtree;
        /// <summary>
        /// The display name of the private endpoint.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetOperationsInsightsPrivateEndpointsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The flag is to identify if private endpoint is used for rac database or not
        /// </summary>
        public readonly bool? IsUsedForRacDbs;
        /// <summary>
        /// The list of operations_insights_private_endpoint_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetOperationsInsightsPrivateEndpointsOperationsInsightsPrivateEndpointCollectionResult> OperationsInsightsPrivateEndpointCollections;
        public readonly string? OpsiPrivateEndpointId;
        /// <summary>
        /// The current state of the private endpoint.
        /// </summary>
        public readonly ImmutableArray<string> States;
        /// <summary>
        /// The OCID of the VCN.
        /// </summary>
        public readonly string? VcnId;

        [OutputConstructor]
        private GetOperationsInsightsPrivateEndpointsResult(
            string? compartmentId,

            bool? compartmentIdInSubtree,

            string? displayName,

            ImmutableArray<Outputs.GetOperationsInsightsPrivateEndpointsFilterResult> filters,

            string id,

            bool? isUsedForRacDbs,

            ImmutableArray<Outputs.GetOperationsInsightsPrivateEndpointsOperationsInsightsPrivateEndpointCollectionResult> operationsInsightsPrivateEndpointCollections,

            string? opsiPrivateEndpointId,

            ImmutableArray<string> states,

            string? vcnId)
        {
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            IsUsedForRacDbs = isUsedForRacDbs;
            OperationsInsightsPrivateEndpointCollections = operationsInsightsPrivateEndpointCollections;
            OpsiPrivateEndpointId = opsiPrivateEndpointId;
            States = states;
            VcnId = vcnId;
        }
    }
}