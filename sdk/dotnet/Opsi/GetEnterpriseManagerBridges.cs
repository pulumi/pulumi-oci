// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Opsi
{
    public static class GetEnterpriseManagerBridges
    {
        /// <summary>
        /// This data source provides the list of Enterprise Manager Bridges in Oracle Cloud Infrastructure Opsi service.
        /// 
        /// Gets a list of Operations Insights Enterprise Manager bridges. Either compartmentId or id must be specified.
        /// When both compartmentId and compartmentIdInSubtree are specified, a list of bridges in that compartment and in all sub-compartments will be returned.
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
        ///     var testEnterpriseManagerBridges = Oci.Opsi.GetEnterpriseManagerBridges.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         CompartmentIdInSubtree = @var.Enterprise_manager_bridge_compartment_id_in_subtree,
        ///         DisplayName = @var.Enterprise_manager_bridge_display_name,
        ///         Id = @var.Enterprise_manager_bridge_id,
        ///         States = @var.Enterprise_manager_bridge_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetEnterpriseManagerBridgesResult> InvokeAsync(GetEnterpriseManagerBridgesArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetEnterpriseManagerBridgesResult>("oci:Opsi/getEnterpriseManagerBridges:getEnterpriseManagerBridges", args ?? new GetEnterpriseManagerBridgesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Enterprise Manager Bridges in Oracle Cloud Infrastructure Opsi service.
        /// 
        /// Gets a list of Operations Insights Enterprise Manager bridges. Either compartmentId or id must be specified.
        /// When both compartmentId and compartmentIdInSubtree are specified, a list of bridges in that compartment and in all sub-compartments will be returned.
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
        ///     var testEnterpriseManagerBridges = Oci.Opsi.GetEnterpriseManagerBridges.Invoke(new()
        ///     {
        ///         CompartmentId = @var.Compartment_id,
        ///         CompartmentIdInSubtree = @var.Enterprise_manager_bridge_compartment_id_in_subtree,
        ///         DisplayName = @var.Enterprise_manager_bridge_display_name,
        ///         Id = @var.Enterprise_manager_bridge_id,
        ///         States = @var.Enterprise_manager_bridge_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetEnterpriseManagerBridgesResult> Invoke(GetEnterpriseManagerBridgesInvokeArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetEnterpriseManagerBridgesResult>("oci:Opsi/getEnterpriseManagerBridges:getEnterpriseManagerBridges", args ?? new GetEnterpriseManagerBridgesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetEnterpriseManagerBridgesArgs : global::Pulumi.InvokeArgs
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
        private List<Inputs.GetEnterpriseManagerBridgesFilterArgs>? _filters;
        public List<Inputs.GetEnterpriseManagerBridgesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetEnterpriseManagerBridgesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique Enterprise Manager bridge identifier
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

        public GetEnterpriseManagerBridgesArgs()
        {
        }
        public static new GetEnterpriseManagerBridgesArgs Empty => new GetEnterpriseManagerBridgesArgs();
    }

    public sealed class GetEnterpriseManagerBridgesInvokeArgs : global::Pulumi.InvokeArgs
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
        private InputList<Inputs.GetEnterpriseManagerBridgesFilterInputArgs>? _filters;
        public InputList<Inputs.GetEnterpriseManagerBridgesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetEnterpriseManagerBridgesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique Enterprise Manager bridge identifier
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

        public GetEnterpriseManagerBridgesInvokeArgs()
        {
        }
        public static new GetEnterpriseManagerBridgesInvokeArgs Empty => new GetEnterpriseManagerBridgesInvokeArgs();
    }


    [OutputType]
    public sealed class GetEnterpriseManagerBridgesResult
    {
        /// <summary>
        /// Compartment identifier of the Enterprise Manager bridge
        /// </summary>
        public readonly string? CompartmentId;
        public readonly bool? CompartmentIdInSubtree;
        /// <summary>
        /// User-friedly name of Enterprise Manager Bridge that does not have to be unique.
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// The list of enterprise_manager_bridge_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetEnterpriseManagerBridgesEnterpriseManagerBridgeCollectionResult> EnterpriseManagerBridgeCollections;
        public readonly ImmutableArray<Outputs.GetEnterpriseManagerBridgesFilterResult> Filters;
        /// <summary>
        /// Enterprise Manager bridge identifier
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The current state of the Enterprise Manager bridge.
        /// </summary>
        public readonly ImmutableArray<string> States;

        [OutputConstructor]
        private GetEnterpriseManagerBridgesResult(
            string? compartmentId,

            bool? compartmentIdInSubtree,

            string? displayName,

            ImmutableArray<Outputs.GetEnterpriseManagerBridgesEnterpriseManagerBridgeCollectionResult> enterpriseManagerBridgeCollections,

            ImmutableArray<Outputs.GetEnterpriseManagerBridgesFilterResult> filters,

            string? id,

            ImmutableArray<string> states)
        {
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            DisplayName = displayName;
            EnterpriseManagerBridgeCollections = enterpriseManagerBridgeCollections;
            Filters = filters;
            Id = id;
            States = states;
        }
    }
}