// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ComputeCloud
{
    public static class GetAtCustomerCccUpgradeSchedules
    {
        /// <summary>
        /// This data source provides the list of Ccc Upgrade Schedules in Oracle Cloud Infrastructure Compute Cloud At Customer service.
        /// 
        /// Returns a list of Compute Cloud@Customer upgrade schedules.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testCccUpgradeSchedules = Oci.ComputeCloud.GetAtCustomerCccUpgradeSchedules.Invoke(new()
        ///     {
        ///         AccessLevel = cccUpgradeScheduleAccessLevel,
        ///         CccUpgradeScheduleId = testCccUpgradeSchedule.Id,
        ///         CompartmentId = compartmentId,
        ///         CompartmentIdInSubtree = cccUpgradeScheduleCompartmentIdInSubtree,
        ///         DisplayName = cccUpgradeScheduleDisplayName,
        ///         DisplayNameContains = cccUpgradeScheduleDisplayNameContains,
        ///         State = cccUpgradeScheduleState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetAtCustomerCccUpgradeSchedulesResult> InvokeAsync(GetAtCustomerCccUpgradeSchedulesArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetAtCustomerCccUpgradeSchedulesResult>("oci:ComputeCloud/getAtCustomerCccUpgradeSchedules:getAtCustomerCccUpgradeSchedules", args ?? new GetAtCustomerCccUpgradeSchedulesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Ccc Upgrade Schedules in Oracle Cloud Infrastructure Compute Cloud At Customer service.
        /// 
        /// Returns a list of Compute Cloud@Customer upgrade schedules.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testCccUpgradeSchedules = Oci.ComputeCloud.GetAtCustomerCccUpgradeSchedules.Invoke(new()
        ///     {
        ///         AccessLevel = cccUpgradeScheduleAccessLevel,
        ///         CccUpgradeScheduleId = testCccUpgradeSchedule.Id,
        ///         CompartmentId = compartmentId,
        ///         CompartmentIdInSubtree = cccUpgradeScheduleCompartmentIdInSubtree,
        ///         DisplayName = cccUpgradeScheduleDisplayName,
        ///         DisplayNameContains = cccUpgradeScheduleDisplayNameContains,
        ///         State = cccUpgradeScheduleState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAtCustomerCccUpgradeSchedulesResult> Invoke(GetAtCustomerCccUpgradeSchedulesInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetAtCustomerCccUpgradeSchedulesResult>("oci:ComputeCloud/getAtCustomerCccUpgradeSchedules:getAtCustomerCccUpgradeSchedules", args ?? new GetAtCustomerCccUpgradeSchedulesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Ccc Upgrade Schedules in Oracle Cloud Infrastructure Compute Cloud At Customer service.
        /// 
        /// Returns a list of Compute Cloud@Customer upgrade schedules.
        /// 
        /// 
        /// ## Example Usage
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using System.Linq;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testCccUpgradeSchedules = Oci.ComputeCloud.GetAtCustomerCccUpgradeSchedules.Invoke(new()
        ///     {
        ///         AccessLevel = cccUpgradeScheduleAccessLevel,
        ///         CccUpgradeScheduleId = testCccUpgradeSchedule.Id,
        ///         CompartmentId = compartmentId,
        ///         CompartmentIdInSubtree = cccUpgradeScheduleCompartmentIdInSubtree,
        ///         DisplayName = cccUpgradeScheduleDisplayName,
        ///         DisplayNameContains = cccUpgradeScheduleDisplayNameContains,
        ///         State = cccUpgradeScheduleState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAtCustomerCccUpgradeSchedulesResult> Invoke(GetAtCustomerCccUpgradeSchedulesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetAtCustomerCccUpgradeSchedulesResult>("oci:ComputeCloud/getAtCustomerCccUpgradeSchedules:getAtCustomerCccUpgradeSchedules", args ?? new GetAtCustomerCccUpgradeSchedulesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAtCustomerCccUpgradeSchedulesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public string? AccessLevel { get; set; }

        /// <summary>
        /// Compute Cloud@Customer upgrade schedule [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("cccUpgradeScheduleId")]
        public string? CccUpgradeScheduleId { get; set; }

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
        private List<Inputs.GetAtCustomerCccUpgradeSchedulesFilterArgs>? _filters;
        public List<Inputs.GetAtCustomerCccUpgradeSchedulesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAtCustomerCccUpgradeSchedulesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return resources only when their lifecycleState matches the given lifecycleState.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetAtCustomerCccUpgradeSchedulesArgs()
        {
        }
        public static new GetAtCustomerCccUpgradeSchedulesArgs Empty => new GetAtCustomerCccUpgradeSchedulesArgs();
    }

    public sealed class GetAtCustomerCccUpgradeSchedulesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
        /// </summary>
        [Input("accessLevel")]
        public Input<string>? AccessLevel { get; set; }

        /// <summary>
        /// Compute Cloud@Customer upgrade schedule [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("cccUpgradeScheduleId")]
        public Input<string>? CccUpgradeScheduleId { get; set; }

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
        private InputList<Inputs.GetAtCustomerCccUpgradeSchedulesFilterInputArgs>? _filters;
        public InputList<Inputs.GetAtCustomerCccUpgradeSchedulesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetAtCustomerCccUpgradeSchedulesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return resources only when their lifecycleState matches the given lifecycleState.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetAtCustomerCccUpgradeSchedulesInvokeArgs()
        {
        }
        public static new GetAtCustomerCccUpgradeSchedulesInvokeArgs Empty => new GetAtCustomerCccUpgradeSchedulesInvokeArgs();
    }


    [OutputType]
    public sealed class GetAtCustomerCccUpgradeSchedulesResult
    {
        public readonly string? AccessLevel;
        /// <summary>
        /// The list of ccc_upgrade_schedule_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAtCustomerCccUpgradeSchedulesCccUpgradeScheduleCollectionResult> CccUpgradeScheduleCollections;
        public readonly string? CccUpgradeScheduleId;
        /// <summary>
        /// Compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Compute Cloud@Customer upgrade schedule.
        /// </summary>
        public readonly string? CompartmentId;
        public readonly bool? CompartmentIdInSubtree;
        /// <summary>
        /// Compute Cloud@Customer upgrade schedule display name. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly string? DisplayNameContains;
        public readonly ImmutableArray<Outputs.GetAtCustomerCccUpgradeSchedulesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Lifecycle state of the resource.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetAtCustomerCccUpgradeSchedulesResult(
            string? accessLevel,

            ImmutableArray<Outputs.GetAtCustomerCccUpgradeSchedulesCccUpgradeScheduleCollectionResult> cccUpgradeScheduleCollections,

            string? cccUpgradeScheduleId,

            string? compartmentId,

            bool? compartmentIdInSubtree,

            string? displayName,

            string? displayNameContains,

            ImmutableArray<Outputs.GetAtCustomerCccUpgradeSchedulesFilterResult> filters,

            string id,

            string? state)
        {
            AccessLevel = accessLevel;
            CccUpgradeScheduleCollections = cccUpgradeScheduleCollections;
            CccUpgradeScheduleId = cccUpgradeScheduleId;
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
