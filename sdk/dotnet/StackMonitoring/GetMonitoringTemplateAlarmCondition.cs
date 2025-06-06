// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring
{
    public static class GetMonitoringTemplateAlarmCondition
    {
        /// <summary>
        /// This data source provides details about a specific Monitoring Template Alarm Condition resource in Oracle Cloud Infrastructure Stack Monitoring service.
        /// 
        /// Gets a Alarm Condition by identifier.
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
        ///     var testMonitoringTemplateAlarmCondition = Oci.StackMonitoring.GetMonitoringTemplateAlarmCondition.Invoke(new()
        ///     {
        ///         AlarmConditionId = testAlarmCondition.Id,
        ///         MonitoringTemplateId = testMonitoringTemplate.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetMonitoringTemplateAlarmConditionResult> InvokeAsync(GetMonitoringTemplateAlarmConditionArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetMonitoringTemplateAlarmConditionResult>("oci:StackMonitoring/getMonitoringTemplateAlarmCondition:getMonitoringTemplateAlarmCondition", args ?? new GetMonitoringTemplateAlarmConditionArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Monitoring Template Alarm Condition resource in Oracle Cloud Infrastructure Stack Monitoring service.
        /// 
        /// Gets a Alarm Condition by identifier.
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
        ///     var testMonitoringTemplateAlarmCondition = Oci.StackMonitoring.GetMonitoringTemplateAlarmCondition.Invoke(new()
        ///     {
        ///         AlarmConditionId = testAlarmCondition.Id,
        ///         MonitoringTemplateId = testMonitoringTemplate.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetMonitoringTemplateAlarmConditionResult> Invoke(GetMonitoringTemplateAlarmConditionInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetMonitoringTemplateAlarmConditionResult>("oci:StackMonitoring/getMonitoringTemplateAlarmCondition:getMonitoringTemplateAlarmCondition", args ?? new GetMonitoringTemplateAlarmConditionInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Monitoring Template Alarm Condition resource in Oracle Cloud Infrastructure Stack Monitoring service.
        /// 
        /// Gets a Alarm Condition by identifier.
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
        ///     var testMonitoringTemplateAlarmCondition = Oci.StackMonitoring.GetMonitoringTemplateAlarmCondition.Invoke(new()
        ///     {
        ///         AlarmConditionId = testAlarmCondition.Id,
        ///         MonitoringTemplateId = testMonitoringTemplate.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetMonitoringTemplateAlarmConditionResult> Invoke(GetMonitoringTemplateAlarmConditionInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetMonitoringTemplateAlarmConditionResult>("oci:StackMonitoring/getMonitoringTemplateAlarmCondition:getMonitoringTemplateAlarmCondition", args ?? new GetMonitoringTemplateAlarmConditionInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetMonitoringTemplateAlarmConditionArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm condition.
        /// </summary>
        [Input("alarmConditionId", required: true)]
        public string AlarmConditionId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
        /// </summary>
        [Input("monitoringTemplateId", required: true)]
        public string MonitoringTemplateId { get; set; } = null!;

        public GetMonitoringTemplateAlarmConditionArgs()
        {
        }
        public static new GetMonitoringTemplateAlarmConditionArgs Empty => new GetMonitoringTemplateAlarmConditionArgs();
    }

    public sealed class GetMonitoringTemplateAlarmConditionInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm condition.
        /// </summary>
        [Input("alarmConditionId", required: true)]
        public Input<string> AlarmConditionId { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
        /// </summary>
        [Input("monitoringTemplateId", required: true)]
        public Input<string> MonitoringTemplateId { get; set; } = null!;

        public GetMonitoringTemplateAlarmConditionInvokeArgs()
        {
        }
        public static new GetMonitoringTemplateAlarmConditionInvokeArgs Empty => new GetMonitoringTemplateAlarmConditionInvokeArgs();
    }


    [OutputType]
    public sealed class GetMonitoringTemplateAlarmConditionResult
    {
        public readonly string AlarmConditionId;
        /// <summary>
        /// The OCID of the composite resource type like EBS/PEOPLE_SOFT.
        /// </summary>
        public readonly string CompositeType;
        /// <summary>
        /// Type of defined monitoring template.
        /// </summary>
        public readonly string ConditionType;
        /// <summary>
        /// Monitoring template conditions
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMonitoringTemplateAlarmConditionConditionResult> Conditions;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Alarm Condition.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The metric name.
        /// </summary>
        public readonly string MetricName;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
        /// </summary>
        public readonly string MonitoringTemplateId;
        /// <summary>
        /// The stack monitoring service or application emitting the metric that is evaluated by the alarm.
        /// </summary>
        public readonly string Namespace;
        /// <summary>
        /// The resource type OCID.
        /// </summary>
        public readonly string ResourceType;
        /// <summary>
        /// The current lifecycle state of the monitoring template
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The current status of the monitoring template i.e. whether it is Published or Unpublished
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// The date and time the alarm condition was created. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the alarm condition was updated. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetMonitoringTemplateAlarmConditionResult(
            string alarmConditionId,

            string compositeType,

            string conditionType,

            ImmutableArray<Outputs.GetMonitoringTemplateAlarmConditionConditionResult> conditions,

            ImmutableDictionary<string, string> definedTags,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            string metricName,

            string monitoringTemplateId,

            string @namespace,

            string resourceType,

            string state,

            string status,

            ImmutableDictionary<string, string> systemTags,

            string timeCreated,

            string timeUpdated)
        {
            AlarmConditionId = alarmConditionId;
            CompositeType = compositeType;
            ConditionType = conditionType;
            Conditions = conditions;
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            Id = id;
            MetricName = metricName;
            MonitoringTemplateId = monitoringTemplateId;
            Namespace = @namespace;
            ResourceType = resourceType;
            State = state;
            Status = status;
            SystemTags = systemTags;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}
