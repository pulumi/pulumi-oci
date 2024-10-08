// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Monitoring
{
    public static class GetAlarmSuppressions
    {
        /// <summary>
        /// This data source provides the list of Alarm Suppressions in Oracle Cloud Infrastructure Monitoring service.
        /// 
        /// Lists alarm suppressions for the specified alarm.
        /// Only dimension-level suppressions are listed. Alarm-level suppressions are not listed.
        /// 
        /// For important limits information, see
        /// [Limits on Monitoring](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#limits).
        /// 
        /// This call is subject to a Monitoring limit that applies to the total number of requests across all alarm operations.
        /// Monitoring might throttle this call to reject an otherwise valid request when the total rate of alarm operations exceeds 10 requests,
        /// or transactions, per second (TPS) for a given tenancy.
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
        ///     var testAlarmSuppressions = Oci.Monitoring.GetAlarmSuppressions.Invoke(new()
        ///     {
        ///         AlarmId = testAlarm.Id,
        ///         DisplayName = alarmSuppressionDisplayName,
        ///         State = alarmSuppressionState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetAlarmSuppressionsResult> InvokeAsync(GetAlarmSuppressionsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetAlarmSuppressionsResult>("oci:Monitoring/getAlarmSuppressions:getAlarmSuppressions", args ?? new GetAlarmSuppressionsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Alarm Suppressions in Oracle Cloud Infrastructure Monitoring service.
        /// 
        /// Lists alarm suppressions for the specified alarm.
        /// Only dimension-level suppressions are listed. Alarm-level suppressions are not listed.
        /// 
        /// For important limits information, see
        /// [Limits on Monitoring](https://docs.cloud.oracle.com/iaas/Content/Monitoring/Concepts/monitoringoverview.htm#limits).
        /// 
        /// This call is subject to a Monitoring limit that applies to the total number of requests across all alarm operations.
        /// Monitoring might throttle this call to reject an otherwise valid request when the total rate of alarm operations exceeds 10 requests,
        /// or transactions, per second (TPS) for a given tenancy.
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
        ///     var testAlarmSuppressions = Oci.Monitoring.GetAlarmSuppressions.Invoke(new()
        ///     {
        ///         AlarmId = testAlarm.Id,
        ///         DisplayName = alarmSuppressionDisplayName,
        ///         State = alarmSuppressionState,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetAlarmSuppressionsResult> Invoke(GetAlarmSuppressionsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetAlarmSuppressionsResult>("oci:Monitoring/getAlarmSuppressions:getAlarmSuppressions", args ?? new GetAlarmSuppressionsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetAlarmSuppressionsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm that is the target of the alarm suppression.
        /// </summary>
        [Input("alarmId", required: true)]
        public string AlarmId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly. Use this filter to list a alarm suppression by name. Alternatively, when you know the alarm suppression OCID, use the GetAlarmSuppression operation.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetAlarmSuppressionsFilterArgs>? _filters;
        public List<Inputs.GetAlarmSuppressionsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetAlarmSuppressionsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly. When not specified, only resources in the ACTIVE lifecycle state are listed.
        /// </summary>
        [Input("state")]
        public string? State { get; set; }

        public GetAlarmSuppressionsArgs()
        {
        }
        public static new GetAlarmSuppressionsArgs Empty => new GetAlarmSuppressionsArgs();
    }

    public sealed class GetAlarmSuppressionsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm that is the target of the alarm suppression.
        /// </summary>
        [Input("alarmId", required: true)]
        public Input<string> AlarmId { get; set; } = null!;

        /// <summary>
        /// A filter to return only resources that match the given display name exactly. Use this filter to list a alarm suppression by name. Alternatively, when you know the alarm suppression OCID, use the GetAlarmSuppression operation.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetAlarmSuppressionsFilterInputArgs>? _filters;
        public InputList<Inputs.GetAlarmSuppressionsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetAlarmSuppressionsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly. When not specified, only resources in the ACTIVE lifecycle state are listed.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        public GetAlarmSuppressionsInvokeArgs()
        {
        }
        public static new GetAlarmSuppressionsInvokeArgs Empty => new GetAlarmSuppressionsInvokeArgs();
    }


    [OutputType]
    public sealed class GetAlarmSuppressionsResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm that is the target of the alarm suppression.
        /// </summary>
        public readonly string AlarmId;
        /// <summary>
        /// The list of alarm_suppression_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetAlarmSuppressionsAlarmSuppressionCollectionResult> AlarmSuppressionCollections;
        /// <summary>
        /// A user-friendly name for the alarm suppression. It does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetAlarmSuppressionsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The current lifecycle state of the alarm suppression.  Example: `DELETED`
        /// </summary>
        public readonly string? State;

        [OutputConstructor]
        private GetAlarmSuppressionsResult(
            string alarmId,

            ImmutableArray<Outputs.GetAlarmSuppressionsAlarmSuppressionCollectionResult> alarmSuppressionCollections,

            string? displayName,

            ImmutableArray<Outputs.GetAlarmSuppressionsFilterResult> filters,

            string id,

            string? state)
        {
            AlarmId = alarmId;
            AlarmSuppressionCollections = alarmSuppressionCollections;
            DisplayName = displayName;
            Filters = filters;
            Id = id;
            State = state;
        }
    }
}
