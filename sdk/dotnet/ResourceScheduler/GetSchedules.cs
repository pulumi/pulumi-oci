// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ResourceScheduler
{
    public static class GetSchedules
    {
        /// <summary>
        /// This data source provides the list of Schedules in Oracle Cloud Infrastructure Resource Scheduler service.
        /// 
        /// This API gets a list of schedules. You must provide either a compartmentId or a scheduleId or both. You can list resources in this compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This is required unless a specific schedule ID is passed.
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
        ///     var testSchedules = Oci.ResourceScheduler.GetSchedules.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = scheduleDisplayName,
        ///         ResourceId = testResource.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetSchedulesResult> InvokeAsync(GetSchedulesArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetSchedulesResult>("oci:ResourceScheduler/getSchedules:getSchedules", args ?? new GetSchedulesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Schedules in Oracle Cloud Infrastructure Resource Scheduler service.
        /// 
        /// This API gets a list of schedules. You must provide either a compartmentId or a scheduleId or both. You can list resources in this compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This is required unless a specific schedule ID is passed.
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
        ///     var testSchedules = Oci.ResourceScheduler.GetSchedules.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = scheduleDisplayName,
        ///         ResourceId = testResource.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSchedulesResult> Invoke(GetSchedulesInvokeArgs? args = null, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetSchedulesResult>("oci:ResourceScheduler/getSchedules:getSchedules", args ?? new GetSchedulesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Schedules in Oracle Cloud Infrastructure Resource Scheduler service.
        /// 
        /// This API gets a list of schedules. You must provide either a compartmentId or a scheduleId or both. You can list resources in this compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). This is required unless a specific schedule ID is passed.
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
        ///     var testSchedules = Oci.ResourceScheduler.GetSchedules.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = scheduleDisplayName,
        ///         ResourceId = testResource.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSchedulesResult> Invoke(GetSchedulesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetSchedulesResult>("oci:ResourceScheduler/getSchedules:getSchedules", args ?? new GetSchedulesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSchedulesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// This is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources. You need to at least provide either `compartment_id` or `schedule_id` or both.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// This is a filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetSchedulesFilterArgs>? _filters;
        public List<Inputs.GetSchedulesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetSchedulesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// This is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource affected by the work request.
        /// </summary>
        [Input("resourceId")]
        public string? ResourceId { get; set; }

        /// <summary>
        /// This is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the schedule.  You need to at least provide either `compartment_id` or `schedule_id` or both.
        /// </summary>
        [Input("scheduleId")]
        public string? ScheduleId { get; set; }

        /// <summary>
        /// This is a filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetSchedulesArgs()
        {
        }
        public static new GetSchedulesArgs Empty => new GetSchedulesArgs();
    }

    public sealed class GetSchedulesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// This is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources. You need to at least provide either `compartment_id` or `schedule_id` or both.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// This is a filter to return only resources that match the given display name exactly.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetSchedulesFilterInputArgs>? _filters;
        public InputList<Inputs.GetSchedulesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetSchedulesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// This is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource affected by the work request.
        /// </summary>
        [Input("resourceId")]
        public Input<string>? ResourceId { get; set; }

        /// <summary>
        /// This is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the schedule.  You need to at least provide either `compartment_id` or `schedule_id` or both.
        /// </summary>
        [Input("scheduleId")]
        public Input<string>? ScheduleId { get; set; }

        /// <summary>
        /// This is a filter to return only resources that match the given lifecycle state. The state value is case-insensitive.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetSchedulesInvokeArgs()
        {
        }
        public static new GetSchedulesInvokeArgs Empty => new GetSchedulesInvokeArgs();
    }


    [OutputType]
    public sealed class GetSchedulesResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the schedule is created
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// This is a user-friendly name for the schedule. It does not have to be unique, and it's changeable.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetSchedulesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string? ResourceId;
        /// <summary>
        /// The list of schedule_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSchedulesScheduleCollectionResult> ScheduleCollections;
        public readonly string? ScheduleId;
        /// <summary>
        /// This is the current state of a schedule.
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetSchedulesResult(
            string? compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetSchedulesFilterResult> filters,

            string id,

            string? resourceId,

            ImmutableArray<Outputs.GetSchedulesScheduleCollectionResult> scheduleCollections,

            string? scheduleId,

            string? state)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            ResourceId = resourceId;
            ScheduleCollections = scheduleCollections;
            ScheduleId = scheduleId;
            State = state;
        }
    }
}
