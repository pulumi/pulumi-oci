// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DisasterRecovery
{
    public static class GetDrPlanExecution
    {
        /// <summary>
        /// This data source provides details about a specific Dr Plan Execution resource in Oracle Cloud Infrastructure Disaster Recovery service.
        /// 
        /// Get details for the DR plan execution identified by *drPlanExecutionId*.
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
        ///     var testDrPlanExecution = Oci.DisasterRecovery.GetDrPlanExecution.Invoke(new()
        ///     {
        ///         DrPlanExecutionId = testDrPlanExecutionOciDisasterRecoveryDrPlanExecution.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetDrPlanExecutionResult> InvokeAsync(GetDrPlanExecutionArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetDrPlanExecutionResult>("oci:DisasterRecovery/getDrPlanExecution:getDrPlanExecution", args ?? new GetDrPlanExecutionArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Dr Plan Execution resource in Oracle Cloud Infrastructure Disaster Recovery service.
        /// 
        /// Get details for the DR plan execution identified by *drPlanExecutionId*.
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
        ///     var testDrPlanExecution = Oci.DisasterRecovery.GetDrPlanExecution.Invoke(new()
        ///     {
        ///         DrPlanExecutionId = testDrPlanExecutionOciDisasterRecoveryDrPlanExecution.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDrPlanExecutionResult> Invoke(GetDrPlanExecutionInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetDrPlanExecutionResult>("oci:DisasterRecovery/getDrPlanExecution:getDrPlanExecution", args ?? new GetDrPlanExecutionInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Dr Plan Execution resource in Oracle Cloud Infrastructure Disaster Recovery service.
        /// 
        /// Get details for the DR plan execution identified by *drPlanExecutionId*.
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
        ///     var testDrPlanExecution = Oci.DisasterRecovery.GetDrPlanExecution.Invoke(new()
        ///     {
        ///         DrPlanExecutionId = testDrPlanExecutionOciDisasterRecoveryDrPlanExecution.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetDrPlanExecutionResult> Invoke(GetDrPlanExecutionInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetDrPlanExecutionResult>("oci:DisasterRecovery/getDrPlanExecution:getDrPlanExecution", args ?? new GetDrPlanExecutionInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDrPlanExecutionArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the DR plan execution.  Example: `ocid1.drplanexecution.oc1..uniqueID`
        /// </summary>
        [Input("drPlanExecutionId", required: true)]
        public string DrPlanExecutionId { get; set; } = null!;

        public GetDrPlanExecutionArgs()
        {
        }
        public static new GetDrPlanExecutionArgs Empty => new GetDrPlanExecutionArgs();
    }

    public sealed class GetDrPlanExecutionInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The OCID of the DR plan execution.  Example: `ocid1.drplanexecution.oc1..uniqueID`
        /// </summary>
        [Input("drPlanExecutionId", required: true)]
        public Input<string> DrPlanExecutionId { get; set; } = null!;

        public GetDrPlanExecutionInvokeArgs()
        {
        }
        public static new GetDrPlanExecutionInvokeArgs Empty => new GetDrPlanExecutionInvokeArgs();
    }


    [OutputType]
    public sealed class GetDrPlanExecutionResult
    {
        /// <summary>
        /// The OCID of the compartment containing this DR plan execution.  Example: `ocid1.compartment.oc1..uniqueID`
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"Operations.CostCenter": "42"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// The display name of the step execution.  Example: `DATABASE_SWITCHOVER`
        /// </summary>
        public readonly string DisplayName;
        public readonly string DrPlanExecutionId;
        /// <summary>
        /// The OCID of the DR protection group to which this DR plan execution belongs.  Example: `ocid1.drprotectiongroup.oc1..uniqueID`
        /// </summary>
        public readonly string DrProtectionGroupId;
        /// <summary>
        /// The total duration in seconds taken to complete the step execution.  Example: `35`
        /// </summary>
        public readonly int ExecutionDurationInSec;
        /// <summary>
        /// The options for a plan execution.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDrPlanExecutionExecutionOptionResult> ExecutionOptions;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// A list of groups executed in this DR plan execution.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDrPlanExecutionGroupExecutionResult> GroupExecutions;
        /// <summary>
        /// The OCID of the DR plan execution.  Example: `ocid1.drplanexecution.oc1..uniqueID`
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A message describing the DR plan execution's current state in more detail.
        /// </summary>
        public readonly string LifeCycleDetails;
        /// <summary>
        /// The details of an object storage log location for a DR protection group.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetDrPlanExecutionLogLocationResult> LogLocations;
        /// <summary>
        /// The OCID of peer DR protection group associated with this plan's DR protection group.  Example: `ocid1.drprotectiongroup.oc1..uniqueID`
        /// </summary>
        public readonly string PeerDrProtectionGroupId;
        /// <summary>
        /// The region of the peer DR protection group associated with this plan's DR protection group.  Example: `us-ashburn-1`
        /// </summary>
        public readonly string PeerRegion;
        /// <summary>
        /// The type of the DR plan executed.
        /// </summary>
        public readonly string PlanExecutionType;
        /// <summary>
        /// The OCID of the DR plan.  Example: `ocid1.drplan.oc1..uniqueID`
        /// </summary>
        public readonly string PlanId;
        /// <summary>
        /// The current state of the DR plan execution.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time at which DR plan execution was created. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time at which DR plan execution succeeded, failed, was paused, or was canceled. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        public readonly string TimeEnded;
        /// <summary>
        /// The date and time at which DR plan execution began. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        public readonly string TimeStarted;
        /// <summary>
        /// The time when DR plan execution was last updated. An RFC3339 formatted datetime string.  Example: `2019-03-29T09:36:42Z`
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetDrPlanExecutionResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string displayName,

            string drPlanExecutionId,

            string drProtectionGroupId,

            int executionDurationInSec,

            ImmutableArray<Outputs.GetDrPlanExecutionExecutionOptionResult> executionOptions,

            ImmutableDictionary<string, string> freeformTags,

            ImmutableArray<Outputs.GetDrPlanExecutionGroupExecutionResult> groupExecutions,

            string id,

            string lifeCycleDetails,

            ImmutableArray<Outputs.GetDrPlanExecutionLogLocationResult> logLocations,

            string peerDrProtectionGroupId,

            string peerRegion,

            string planExecutionType,

            string planId,

            string state,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeEnded,

            string timeStarted,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            DisplayName = displayName;
            DrPlanExecutionId = drPlanExecutionId;
            DrProtectionGroupId = drProtectionGroupId;
            ExecutionDurationInSec = executionDurationInSec;
            ExecutionOptions = executionOptions;
            FreeformTags = freeformTags;
            GroupExecutions = groupExecutions;
            Id = id;
            LifeCycleDetails = lifeCycleDetails;
            LogLocations = logLocations;
            PeerDrProtectionGroupId = peerDrProtectionGroupId;
            PeerRegion = peerRegion;
            PlanExecutionType = planExecutionType;
            PlanId = planId;
            State = state;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeEnded = timeEnded;
            TimeStarted = timeStarted;
            TimeUpdated = timeUpdated;
        }
    }
}
