// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ComputeCloud
{
    public static class GetAtCustomerCccInfrastructures
    {
        /// <summary>
        /// This data source provides the list of Ccc Infrastructures in Oracle Cloud Infrastructure Compute Cloud At Customer service.
        /// 
        /// Returns a list of Compute Cloud@Customer infrastructures.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testCccInfrastructures = Oci.ComputeCloud.GetAtCustomerCccInfrastructures.Invoke(new()
        ///     {
        ///         AccessLevel = @var.Ccc_infrastructure_access_level,
        ///         CccInfrastructureId = oci_compute_cloud_at_customer_ccc_infrastructure.Test_ccc_infrastructure.Id,
        ///         CompartmentId = @var.Compartment_id,
        ///         CompartmentIdInSubtree = @var.Ccc_infrastructure_compartment_id_in_subtree,
        ///         DisplayName = @var.Ccc_infrastructure_display_name,
        ///         DisplayNameContains = @var.Ccc_infrastructure_display_name_contains,
        ///         State = @var.Ccc_infrastructure_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetAtCustomerCccInfrastructuresResult> InvokeAsync(GetAtCustomerCccInfrastructuresArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetAtCustomerCccInfrastructuresResult>("oci:ComputeCloud/getAtCustomerCccInfrastructures:getAtCustomerCccInfrastructures", args ?? new GetAtCustomerCccInfrastructuresArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Ccc Infrastructures in Oracle Cloud Infrastructure Compute Cloud At Customer service.
        /// 
        /// Returns a list of Compute Cloud@Customer infrastructures.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testCccInfrastructures = Oci.ComputeCloud.GetAtCustomerCccInfrastructures.Invoke(new()
        ///     {
        ///         AccessLevel = @var.Ccc_infrastructure_access_level,
        ///         CccInfrastructureId = oci_compute_cloud_at_customer_ccc_infrastructure.Test_ccc_infrastructure.Id,
        ///         CompartmentId = @var.Compartment_id,
        ///         CompartmentIdInSubtree = @var.Ccc_infrastructure_compartment_id_in_subtree,
        ///         DisplayName = @var.Ccc_infrastructure_display_name,
        ///         DisplayNameContains = @var.Ccc_infrastructure_display_name_contains,
        ///         State = @var.Ccc_infrastructure_state,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetAtCustomerCccInfrastructuresResult> Invoke(GetAtCustomerCccInfrastructuresInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetAtCustomerCccInfrastructuresResult>("oci:ComputeCloud/getAtCustomerCccInfrastructures:getAtCustomerCccInfrastructures", args ?? new GetAtCustomerCccInfrastructuresInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAtCustomerCccInfrastructuresArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public string? AccessLevel { get; set; }

        /// <summary>
        /// An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for a  Compute Cloud@Customer Infrastructure.
        /// </summary>
        [Input("cccInfrastructureId")]
        public string? CccInfrastructureId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and sub-compartments in the tenancy are returned. Depends on the 'accessLevel' setting.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public bool? CompartmentIdInSubtree { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        /// <summary>
        /// A filter to return only resources whose display name contains the substring.
        /// </summary>
        [Input("displayNameContains")]
        public string? DisplayNameContains { get; set; }

        [Input("filters")]
        private List<Inputs.GetAtCustomerCccInfrastructuresFilterArgs>? _filters;
        public List<Inputs.GetAtCustomerCccInfrastructuresFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAtCustomerCccInfrastructuresFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter used to return only resources that match the given lifecycleState.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetAtCustomerCccInfrastructuresArgs()
        {
        }
        public static new GetAtCustomerCccInfrastructuresArgs Empty => new GetAtCustomerCccInfrastructuresArgs();
    }

    public sealed class GetAtCustomerCccInfrastructuresInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public Input<string>? AccessLevel { get; set; }

        /// <summary>
        /// An [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for a  Compute Cloud@Customer Infrastructure.
        /// </summary>
        [Input("cccInfrastructureId")]
        public Input<string>? CccInfrastructureId { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and sub-compartments in the tenancy are returned. Depends on the 'accessLevel' setting.
        /// </summary>
        [Input("compartmentIdInSubtree")]
        public Input<bool>? CompartmentIdInSubtree { get; set; }

        /// <summary>
        /// A filter to return only resources that match the entire display name given.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// A filter to return only resources whose display name contains the substring.
        /// </summary>
        [Input("displayNameContains")]
        public Input<string>? DisplayNameContains { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetAtCustomerCccInfrastructuresFilterInputArgs>? _filters;
        public InputList<Inputs.GetAtCustomerCccInfrastructuresFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetAtCustomerCccInfrastructuresFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter used to return only resources that match the given lifecycleState.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetAtCustomerCccInfrastructuresInvokeArgs()
        {
        }
        public static new GetAtCustomerCccInfrastructuresInvokeArgs Empty => new GetAtCustomerCccInfrastructuresInvokeArgs();
    }


    [OutputType]
    public sealed class GetAtCustomerCccInfrastructuresResult
    {
        public readonly string? AccessLevel;
        /// <summary>
        /// The list of ccc_infrastructure_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAtCustomerCccInfrastructuresCccInfrastructureCollectionResult> CccInfrastructureCollections;
        public readonly string? CccInfrastructureId;
        /// <summary>
        /// The infrastructure compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string? CompartmentId;
        public readonly bool? CompartmentIdInSubtree;
        /// <summary>
        /// The name that will be used to display the Compute Cloud@Customer infrastructure in the Oracle Cloud Infrastructure console. Does not have to be unique and can be changed. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly string? DisplayNameContains;
        public readonly ImmutableArray<Outputs.GetAtCustomerCccInfrastructuresFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current state of the Compute Cloud@Customer infrastructure.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetAtCustomerCccInfrastructuresResult(
            string? accessLevel,

            ImmutableArray<Outputs.GetAtCustomerCccInfrastructuresCccInfrastructureCollectionResult> cccInfrastructureCollections,

            string? cccInfrastructureId,

            string? compartmentId,

            bool? compartmentIdInSubtree,

            string? displayName,

            string? displayNameContains,

            ImmutableArray<Outputs.GetAtCustomerCccInfrastructuresFilterResult> filters,

            string id,

            string? state)
        {
            AccessLevel = accessLevel;
            CccInfrastructureCollections = cccInfrastructureCollections;
            CccInfrastructureId = cccInfrastructureId;
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            DisplayName = displayName;
            DisplayNameContains = displayNameContains;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}