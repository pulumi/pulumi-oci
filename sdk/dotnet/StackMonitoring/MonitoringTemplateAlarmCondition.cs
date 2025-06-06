// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring
{
    /// <summary>
    /// This resource provides the Monitoring Template Alarm Condition resource in Oracle Cloud Infrastructure Stack Monitoring service.
    /// 
    /// Create a new alarm condition in same monitoringTemplate compartment.
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
    ///     var testMonitoringTemplateAlarmCondition = new Oci.StackMonitoring.MonitoringTemplateAlarmCondition("test_monitoring_template_alarm_condition", new()
    ///     {
    ///         ConditionType = monitoringTemplateAlarmConditionConditionType,
    ///         Conditions = new[]
    ///         {
    ///             new Oci.StackMonitoring.Inputs.MonitoringTemplateAlarmConditionConditionArgs
    ///             {
    ///                 Query = monitoringTemplateAlarmConditionConditionsQuery,
    ///                 Severity = monitoringTemplateAlarmConditionConditionsSeverity,
    ///                 Body = monitoringTemplateAlarmConditionConditionsBody,
    ///                 ShouldAppendNote = monitoringTemplateAlarmConditionConditionsShouldAppendNote,
    ///                 ShouldAppendUrl = monitoringTemplateAlarmConditionConditionsShouldAppendUrl,
    ///                 TriggerDelay = monitoringTemplateAlarmConditionConditionsTriggerDelay,
    ///             },
    ///         },
    ///         MetricName = testMetric.Name,
    ///         MonitoringTemplateId = testMonitoringTemplate.Id,
    ///         Namespace = monitoringTemplateAlarmConditionNamespace,
    ///         ResourceType = monitoringTemplateAlarmConditionResourceType,
    ///         CompositeType = monitoringTemplateAlarmConditionCompositeType,
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// MonitoringTemplateAlarmConditions can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:StackMonitoring/monitoringTemplateAlarmCondition:MonitoringTemplateAlarmCondition test_monitoring_template_alarm_condition "monitoringTemplates/{monitoringTemplateId}/alarmConditions/{alarmConditionId}"
    /// ```
    /// </summary>
    [OciResourceType("oci:StackMonitoring/monitoringTemplateAlarmCondition:MonitoringTemplateAlarmCondition")]
    public partial class MonitoringTemplateAlarmCondition : global::Pulumi.CustomResource
    {
        /// <summary>
        /// (Updatable) The OCID of the composite resource type like EBS/PEOPLE_SOFT.
        /// </summary>
        [Output("compositeType")]
        public Output<string> CompositeType { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Type of defined monitoring template.
        /// </summary>
        [Output("conditionType")]
        public Output<string> ConditionType { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Monitoring template conditions.
        /// </summary>
        [Output("conditions")]
        public Output<ImmutableArray<Outputs.MonitoringTemplateAlarmConditionCondition>> Conditions { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The metric name.
        /// </summary>
        [Output("metricName")]
        public Output<string> MetricName { get; private set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
        /// </summary>
        [Output("monitoringTemplateId")]
        public Output<string> MonitoringTemplateId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The stack monitoring service or application emitting the metric that is evaluated by the alarm.
        /// </summary>
        [Output("namespace")]
        public Output<string> Namespace { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The resource group OCID.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("resourceType")]
        public Output<string> ResourceType { get; private set; } = null!;

        /// <summary>
        /// The current lifecycle state of the monitoring template
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The current status of the monitoring template i.e. whether it is Published or Unpublished
        /// </summary>
        [Output("status")]
        public Output<string> Status { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// The date and time the alarm condition was created. Format defined by RFC3339.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time the alarm condition was updated. Format defined by RFC3339.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;


        /// <summary>
        /// Create a MonitoringTemplateAlarmCondition resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public MonitoringTemplateAlarmCondition(string name, MonitoringTemplateAlarmConditionArgs args, CustomResourceOptions? options = null)
            : base("oci:StackMonitoring/monitoringTemplateAlarmCondition:MonitoringTemplateAlarmCondition", name, args ?? new MonitoringTemplateAlarmConditionArgs(), MakeResourceOptions(options, ""))
        {
        }

        private MonitoringTemplateAlarmCondition(string name, Input<string> id, MonitoringTemplateAlarmConditionState? state = null, CustomResourceOptions? options = null)
            : base("oci:StackMonitoring/monitoringTemplateAlarmCondition:MonitoringTemplateAlarmCondition", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing MonitoringTemplateAlarmCondition resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static MonitoringTemplateAlarmCondition Get(string name, Input<string> id, MonitoringTemplateAlarmConditionState? state = null, CustomResourceOptions? options = null)
        {
            return new MonitoringTemplateAlarmCondition(name, id, state, options);
        }
    }

    public sealed class MonitoringTemplateAlarmConditionArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the composite resource type like EBS/PEOPLE_SOFT.
        /// </summary>
        [Input("compositeType")]
        public Input<string>? CompositeType { get; set; }

        /// <summary>
        /// (Updatable) Type of defined monitoring template.
        /// </summary>
        [Input("conditionType", required: true)]
        public Input<string> ConditionType { get; set; } = null!;

        [Input("conditions", required: true)]
        private InputList<Inputs.MonitoringTemplateAlarmConditionConditionArgs>? _conditions;

        /// <summary>
        /// (Updatable) Monitoring template conditions.
        /// </summary>
        public InputList<Inputs.MonitoringTemplateAlarmConditionConditionArgs> Conditions
        {
            get => _conditions ?? (_conditions = new InputList<Inputs.MonitoringTemplateAlarmConditionConditionArgs>());
            set => _conditions = value;
        }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) The metric name.
        /// </summary>
        [Input("metricName", required: true)]
        public Input<string> MetricName { get; set; } = null!;

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
        /// </summary>
        [Input("monitoringTemplateId", required: true)]
        public Input<string> MonitoringTemplateId { get; set; } = null!;

        /// <summary>
        /// (Updatable) The stack monitoring service or application emitting the metric that is evaluated by the alarm.
        /// </summary>
        [Input("namespace", required: true)]
        public Input<string> Namespace { get; set; } = null!;

        /// <summary>
        /// (Updatable) The resource group OCID.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("resourceType", required: true)]
        public Input<string> ResourceType { get; set; } = null!;

        public MonitoringTemplateAlarmConditionArgs()
        {
        }
        public static new MonitoringTemplateAlarmConditionArgs Empty => new MonitoringTemplateAlarmConditionArgs();
    }

    public sealed class MonitoringTemplateAlarmConditionState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The OCID of the composite resource type like EBS/PEOPLE_SOFT.
        /// </summary>
        [Input("compositeType")]
        public Input<string>? CompositeType { get; set; }

        /// <summary>
        /// (Updatable) Type of defined monitoring template.
        /// </summary>
        [Input("conditionType")]
        public Input<string>? ConditionType { get; set; }

        [Input("conditions")]
        private InputList<Inputs.MonitoringTemplateAlarmConditionConditionGetArgs>? _conditions;

        /// <summary>
        /// (Updatable) Monitoring template conditions.
        /// </summary>
        public InputList<Inputs.MonitoringTemplateAlarmConditionConditionGetArgs> Conditions
        {
            get => _conditions ?? (_conditions = new InputList<Inputs.MonitoringTemplateAlarmConditionConditionGetArgs>());
            set => _conditions = value;
        }

        [Input("definedTags")]
        private InputMap<string>? _definedTags;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public InputMap<string> DefinedTags
        {
            get => _definedTags ?? (_definedTags = new InputMap<string>());
            set => _definedTags = value;
        }

        [Input("freeformTags")]
        private InputMap<string>? _freeformTags;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public InputMap<string> FreeformTags
        {
            get => _freeformTags ?? (_freeformTags = new InputMap<string>());
            set => _freeformTags = value;
        }

        /// <summary>
        /// (Updatable) The metric name.
        /// </summary>
        [Input("metricName")]
        public Input<string>? MetricName { get; set; }

        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
        /// </summary>
        [Input("monitoringTemplateId")]
        public Input<string>? MonitoringTemplateId { get; set; }

        /// <summary>
        /// (Updatable) The stack monitoring service or application emitting the metric that is evaluated by the alarm.
        /// </summary>
        [Input("namespace")]
        public Input<string>? Namespace { get; set; }

        /// <summary>
        /// (Updatable) The resource group OCID.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("resourceType")]
        public Input<string>? ResourceType { get; set; }

        /// <summary>
        /// The current lifecycle state of the monitoring template
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The current status of the monitoring template i.e. whether it is Published or Unpublished
        /// </summary>
        [Input("status")]
        public Input<string>? Status { get; set; }

        [Input("systemTags")]
        private InputMap<string>? _systemTags;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public InputMap<string> SystemTags
        {
            get => _systemTags ?? (_systemTags = new InputMap<string>());
            set => _systemTags = value;
        }

        /// <summary>
        /// The date and time the alarm condition was created. Format defined by RFC3339.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the alarm condition was updated. Format defined by RFC3339.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        public MonitoringTemplateAlarmConditionState()
        {
        }
        public static new MonitoringTemplateAlarmConditionState Empty => new MonitoringTemplateAlarmConditionState();
    }
}
