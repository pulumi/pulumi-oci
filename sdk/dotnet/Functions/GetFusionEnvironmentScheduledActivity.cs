// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Functions
{
    public static class GetFusionEnvironmentScheduledActivity
    {
        /// <summary>
        /// This data source provides details about a specific Fusion Environment Scheduled Activity resource in Oracle Cloud Infrastructure Fusion Apps service.
        /// 
        /// Gets a ScheduledActivity by identifier
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
        ///     var testFusionEnvironmentScheduledActivity = Oci.Functions.GetFusionEnvironmentScheduledActivity.Invoke(new()
        ///     {
        ///         FusionEnvironmentId = testFusionEnvironment.Id,
        ///         ScheduledActivityId = testScheduledActivity.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetFusionEnvironmentScheduledActivityResult> InvokeAsync(GetFusionEnvironmentScheduledActivityArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetFusionEnvironmentScheduledActivityResult>("oci:Functions/getFusionEnvironmentScheduledActivity:getFusionEnvironmentScheduledActivity", args ?? new GetFusionEnvironmentScheduledActivityArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Fusion Environment Scheduled Activity resource in Oracle Cloud Infrastructure Fusion Apps service.
        /// 
        /// Gets a ScheduledActivity by identifier
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
        ///     var testFusionEnvironmentScheduledActivity = Oci.Functions.GetFusionEnvironmentScheduledActivity.Invoke(new()
        ///     {
        ///         FusionEnvironmentId = testFusionEnvironment.Id,
        ///         ScheduledActivityId = testScheduledActivity.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetFusionEnvironmentScheduledActivityResult> Invoke(GetFusionEnvironmentScheduledActivityInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetFusionEnvironmentScheduledActivityResult>("oci:Functions/getFusionEnvironmentScheduledActivity:getFusionEnvironmentScheduledActivity", args ?? new GetFusionEnvironmentScheduledActivityInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Fusion Environment Scheduled Activity resource in Oracle Cloud Infrastructure Fusion Apps service.
        /// 
        /// Gets a ScheduledActivity by identifier
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
        ///     var testFusionEnvironmentScheduledActivity = Oci.Functions.GetFusionEnvironmentScheduledActivity.Invoke(new()
        ///     {
        ///         FusionEnvironmentId = testFusionEnvironment.Id,
        ///         ScheduledActivityId = testScheduledActivity.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetFusionEnvironmentScheduledActivityResult> Invoke(GetFusionEnvironmentScheduledActivityInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetFusionEnvironmentScheduledActivityResult>("oci:Functions/getFusionEnvironmentScheduledActivity:getFusionEnvironmentScheduledActivity", args ?? new GetFusionEnvironmentScheduledActivityInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetFusionEnvironmentScheduledActivityArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// unique FusionEnvironment identifier
        /// </summary>
        [Input("fusionEnvironmentId", required: true)]
        public string FusionEnvironmentId { get; set; } = null!;

        /// <summary>
        /// Unique ScheduledActivity identifier.
        /// </summary>
        [Input("scheduledActivityId", required: true)]
        public string ScheduledActivityId { get; set; } = null!;

        public GetFusionEnvironmentScheduledActivityArgs()
        {
        }
        public static new GetFusionEnvironmentScheduledActivityArgs Empty => new GetFusionEnvironmentScheduledActivityArgs();
    }

    public sealed class GetFusionEnvironmentScheduledActivityInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// unique FusionEnvironment identifier
        /// </summary>
        [Input("fusionEnvironmentId", required: true)]
        public Input<string> FusionEnvironmentId { get; set; } = null!;

        /// <summary>
        /// Unique ScheduledActivity identifier.
        /// </summary>
        [Input("scheduledActivityId", required: true)]
        public Input<string> ScheduledActivityId { get; set; } = null!;

        public GetFusionEnvironmentScheduledActivityInvokeArgs()
        {
        }
        public static new GetFusionEnvironmentScheduledActivityInvokeArgs Empty => new GetFusionEnvironmentScheduledActivityInvokeArgs();
    }


    [OutputType]
    public sealed class GetFusionEnvironmentScheduledActivityResult
    {
        /// <summary>
        /// List of actions
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFusionEnvironmentScheduledActivityActionResult> Actions;
        /// <summary>
        /// Cumulative delay hours
        /// </summary>
        public readonly int DelayInHours;
        /// <summary>
        /// scheduled activity display name, can be renamed.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// FAaaS Environment Identifier.
        /// </summary>
        public readonly string FusionEnvironmentId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// run cadence.
        /// </summary>
        public readonly string RunCycle;
        public readonly string ScheduledActivityId;
        /// <summary>
        /// Service availability / impact during scheduled activity execution up down
        /// </summary>
        public readonly string ServiceAvailability;
        /// <summary>
        /// The current state of the scheduledActivity.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The time the scheduled activity record was created. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Current time the scheduled activity is scheduled to end. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeExpectedFinish;
        /// <summary>
        /// The time the scheduled activity actually completed / cancelled / failed. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeFinished;
        /// <summary>
        /// Current time the scheduled activity is scheduled to start. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeScheduledStart;
        /// <summary>
        /// The time the scheduled activity record was updated. An RFC3339 formatted datetime string.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetFusionEnvironmentScheduledActivityResult(
            ImmutableArray<Outputs.GetFusionEnvironmentScheduledActivityActionResult> actions,

            int delayInHours,

            string displayName,

            string fusionEnvironmentId,

            string id,

            string lifecycleDetails,

            string runCycle,

            string scheduledActivityId,

            string serviceAvailability,

            string state,

            string timeCreated,

            string timeExpectedFinish,

            string timeFinished,

            string timeScheduledStart,

            string timeUpdated)
        {
            Actions = actions;
            DelayInHours = delayInHours;
            DisplayName = displayName;
            FusionEnvironmentId = fusionEnvironmentId;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            RunCycle = runCycle;
            ScheduledActivityId = scheduledActivityId;
            ServiceAvailability = serviceAvailability;
            State = state;
            TimeCreated = timeCreated;
            TimeExpectedFinish = timeExpectedFinish;
            TimeFinished = timeFinished;
            TimeScheduledStart = timeScheduledStart;
            TimeUpdated = timeUpdated;
        }
    }
}
