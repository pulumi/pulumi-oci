// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.MeteringComputation
{
    public static class GetSchedules
    {
        /// <summary>
        /// This data source provides the list of Schedules in Oracle Cloud Infrastructure Metering Computation service.
        /// 
        /// Returns the saved schedule list.
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
        ///     var testSchedules = Oci.MeteringComputation.GetSchedules.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Name = scheduleName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetSchedulesResult> InvokeAsync(GetSchedulesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetSchedulesResult>("oci:MeteringComputation/getSchedules:getSchedules", args ?? new GetSchedulesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Schedules in Oracle Cloud Infrastructure Metering Computation service.
        /// 
        /// Returns the saved schedule list.
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
        ///     var testSchedules = Oci.MeteringComputation.GetSchedules.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Name = scheduleName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSchedulesResult> Invoke(GetSchedulesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetSchedulesResult>("oci:MeteringComputation/getSchedules:getSchedules", args ?? new GetSchedulesInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Schedules in Oracle Cloud Infrastructure Metering Computation service.
        /// 
        /// Returns the saved schedule list.
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
        ///     var testSchedules = Oci.MeteringComputation.GetSchedules.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         Name = scheduleName,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetSchedulesResult> Invoke(GetSchedulesInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetSchedulesResult>("oci:MeteringComputation/getSchedules:getSchedules", args ?? new GetSchedulesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetSchedulesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment ID in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        [Input("filters")]
        private List<Inputs.GetSchedulesFilterArgs>? _filters;

        /// <summary>
        /// The filter object for query usage.
        /// </summary>
        public List<Inputs.GetSchedulesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetSchedulesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The query parameter for filtering by name.
        /// </summary>
        [Input("name")]
        public string? Name { get; set; }

        public GetSchedulesArgs()
        {
        }
        public static new GetSchedulesArgs Empty => new GetSchedulesArgs();
    }

    public sealed class GetSchedulesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The compartment ID in which to list resources.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        [Input("filters")]
        private InputList<Inputs.GetSchedulesFilterInputArgs>? _filters;

        /// <summary>
        /// The filter object for query usage.
        /// </summary>
        public InputList<Inputs.GetSchedulesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetSchedulesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The query parameter for filtering by name.
        /// </summary>
        [Input("name")]
        public Input<string>? Name { get; set; }

        public GetSchedulesInvokeArgs()
        {
        }
        public static new GetSchedulesInvokeArgs Empty => new GetSchedulesInvokeArgs();
    }


    [OutputType]
    public sealed class GetSchedulesResult
    {
        /// <summary>
        /// The customer tenancy.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The filter object for query usage.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSchedulesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The unique name of the schedule created by the user.
        /// </summary>
        public readonly string? Name;
        /// <summary>
        /// The list of schedule_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetSchedulesScheduleCollectionResult> ScheduleCollections;

        [OutputConstructor]
        private GetSchedulesResult(
            string compartmentId,

            ImmutableArray<Outputs.GetSchedulesFilterResult> filters,

            string id,

            string? name,

            ImmutableArray<Outputs.GetSchedulesScheduleCollectionResult> scheduleCollections)
        {
            CompartmentId = compartmentId;
            Filters = filters;
            Id = id;
            Name = name;
            ScheduleCollections = scheduleCollections;
        }
    }
}
