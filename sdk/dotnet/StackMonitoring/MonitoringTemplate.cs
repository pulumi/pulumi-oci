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
    /// This resource provides the Monitoring Template resource in Oracle Cloud Infrastructure Stack Monitoring service.
    /// 
    /// Creates a new monitoring template for a given compartment.
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
    ///     var testMonitoringTemplate = new Oci.StackMonitoring.MonitoringTemplate("test_monitoring_template", new()
    ///     {
    ///         CompartmentId = compartmentId,
    ///         Destinations = monitoringTemplateDestinations,
    ///         DisplayName = monitoringTemplateDisplayName,
    ///         Members = new[]
    ///         {
    ///             new Oci.StackMonitoring.Inputs.MonitoringTemplateMemberArgs
    ///             {
    ///                 Id = monitoringTemplateMembersId,
    ///                 Type = monitoringTemplateMembersType,
    ///                 CompositeType = monitoringTemplateMembersCompositeType,
    ///             },
    ///         },
    ///         DefinedTags = 
    ///         {
    ///             { "foo-namespace.bar-key", "value" },
    ///         },
    ///         Description = monitoringTemplateDescription,
    ///         FreeformTags = 
    ///         {
    ///             { "bar-key", "value" },
    ///         },
    ///         IsAlarmsEnabled = monitoringTemplateIsAlarmsEnabled,
    ///         IsSplitNotificationEnabled = monitoringTemplateIsSplitNotificationEnabled,
    ///         MessageFormat = monitoringTemplateMessageFormat,
    ///         RepeatNotificationDuration = monitoringTemplateRepeatNotificationDuration,
    ///     });
    /// 
    /// });
    /// ```
    /// 
    /// ## Import
    /// 
    /// MonitoringTemplates can be imported using the `id`, e.g.
    /// 
    /// ```sh
    /// $ pulumi import oci:StackMonitoring/monitoringTemplate:MonitoringTemplate test_monitoring_template "id"
    /// ```
    /// </summary>
    [OciResourceType("oci:StackMonitoring/monitoringTemplate:MonitoringTemplate")]
    public partial class MonitoringTemplate : global::Pulumi.CustomResource
    {
        /// <summary>
        /// The OCID of the compartment containing the monitoringTemplate.
        /// </summary>
        [Output("compartmentId")]
        public Output<string> CompartmentId { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        [Output("definedTags")]
        public Output<ImmutableDictionary<string, string>> DefinedTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly description for the monitoring template. It does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Output("description")]
        public Output<string> Description { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A list of destinations for alarm notifications. Each destination is represented by the OCID of a related resource, such as a topic.
        /// </summary>
        [Output("destinations")]
        public Output<ImmutableArray<string>> Destinations { get; private set; } = null!;

        /// <summary>
        /// (Updatable) A user-friendly name for the monitoring template. It is unique and mutable in nature. Avoid entering confidential information.
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        [Output("freeformTags")]
        public Output<ImmutableDictionary<string, string>> FreeformTags { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether the alarm is enabled or disabled, it will be Enabled by default.
        /// </summary>
        [Output("isAlarmsEnabled")]
        public Output<bool> IsAlarmsEnabled { get; private set; } = null!;

        /// <summary>
        /// (Updatable) Whether the alarm notification is enabled or disabled, it will be Enabled by default.
        /// </summary>
        [Output("isSplitNotificationEnabled")]
        public Output<bool> IsSplitNotificationEnabled { get; private set; } = null!;

        /// <summary>
        /// (Updatable) List of members of this monitoring template
        /// </summary>
        [Output("members")]
        public Output<ImmutableArray<Outputs.MonitoringTemplateMember>> Members { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The format to use for alarm notifications.
        /// </summary>
        [Output("messageFormat")]
        public Output<string> MessageFormat { get; private set; } = null!;

        /// <summary>
        /// (Updatable) The frequency for re-submitting alarm notifications, if the alarm keeps firing without interruption. Format defined by ISO 8601. For example, PT4H indicates four hours. Minimum- PT1M. Maximum - P30D.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Output("repeatNotificationDuration")]
        public Output<string> RepeatNotificationDuration { get; private set; } = null!;

        /// <summary>
        /// The current lifecycle state of the monitoring template.
        /// </summary>
        [Output("state")]
        public Output<string> State { get; private set; } = null!;

        /// <summary>
        /// The current status of the monitoring template i.e. whether it is Applied or NotApplied.
        /// </summary>
        [Output("status")]
        public Output<string> Status { get; private set; } = null!;

        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        [Output("systemTags")]
        public Output<ImmutableDictionary<string, string>> SystemTags { get; private set; } = null!;

        /// <summary>
        /// Tenant Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        [Output("tenantId")]
        public Output<string> TenantId { get; private set; } = null!;

        /// <summary>
        /// The date and time the monitoringTemplate was created. Format defined by RFC3339.
        /// </summary>
        [Output("timeCreated")]
        public Output<string> TimeCreated { get; private set; } = null!;

        /// <summary>
        /// The date and time the monitoringTemplate was last updated. Format defined by RFC3339.
        /// </summary>
        [Output("timeUpdated")]
        public Output<string> TimeUpdated { get; private set; } = null!;

        /// <summary>
        /// Total Alarm Conditions
        /// </summary>
        [Output("totalAlarmConditions")]
        public Output<double> TotalAlarmConditions { get; private set; } = null!;

        /// <summary>
        /// Total Applied Alarm Conditions
        /// </summary>
        [Output("totalAppliedAlarmConditions")]
        public Output<double> TotalAppliedAlarmConditions { get; private set; } = null!;


        /// <summary>
        /// Create a MonitoringTemplate resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public MonitoringTemplate(string name, MonitoringTemplateArgs args, CustomResourceOptions? options = null)
            : base("oci:StackMonitoring/monitoringTemplate:MonitoringTemplate", name, args ?? new MonitoringTemplateArgs(), MakeResourceOptions(options, ""))
        {
        }

        private MonitoringTemplate(string name, Input<string> id, MonitoringTemplateState? state = null, CustomResourceOptions? options = null)
            : base("oci:StackMonitoring/monitoringTemplate:MonitoringTemplate", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing MonitoringTemplate resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static MonitoringTemplate Get(string name, Input<string> id, MonitoringTemplateState? state = null, CustomResourceOptions? options = null)
        {
            return new MonitoringTemplate(name, id, state, options);
        }
    }

    public sealed class MonitoringTemplateArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the compartment containing the monitoringTemplate.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

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

        /// <summary>
        /// (Updatable) A user-friendly description for the monitoring template. It does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("destinations", required: true)]
        private InputList<string>? _destinations;

        /// <summary>
        /// (Updatable) A list of destinations for alarm notifications. Each destination is represented by the OCID of a related resource, such as a topic.
        /// </summary>
        public InputList<string> Destinations
        {
            get => _destinations ?? (_destinations = new InputList<string>());
            set => _destinations = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name for the monitoring template. It is unique and mutable in nature. Avoid entering confidential information.
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

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
        /// (Updatable) Whether the alarm is enabled or disabled, it will be Enabled by default.
        /// </summary>
        [Input("isAlarmsEnabled")]
        public Input<bool>? IsAlarmsEnabled { get; set; }

        /// <summary>
        /// (Updatable) Whether the alarm notification is enabled or disabled, it will be Enabled by default.
        /// </summary>
        [Input("isSplitNotificationEnabled")]
        public Input<bool>? IsSplitNotificationEnabled { get; set; }

        [Input("members", required: true)]
        private InputList<Inputs.MonitoringTemplateMemberArgs>? _members;

        /// <summary>
        /// (Updatable) List of members of this monitoring template
        /// </summary>
        public InputList<Inputs.MonitoringTemplateMemberArgs> Members
        {
            get => _members ?? (_members = new InputList<Inputs.MonitoringTemplateMemberArgs>());
            set => _members = value;
        }

        /// <summary>
        /// (Updatable) The format to use for alarm notifications.
        /// </summary>
        [Input("messageFormat")]
        public Input<string>? MessageFormat { get; set; }

        /// <summary>
        /// (Updatable) The frequency for re-submitting alarm notifications, if the alarm keeps firing without interruption. Format defined by ISO 8601. For example, PT4H indicates four hours. Minimum- PT1M. Maximum - P30D.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("repeatNotificationDuration")]
        public Input<string>? RepeatNotificationDuration { get; set; }

        public MonitoringTemplateArgs()
        {
        }
        public static new MonitoringTemplateArgs Empty => new MonitoringTemplateArgs();
    }

    public sealed class MonitoringTemplateState : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The OCID of the compartment containing the monitoringTemplate.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

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

        /// <summary>
        /// (Updatable) A user-friendly description for the monitoring template. It does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("destinations")]
        private InputList<string>? _destinations;

        /// <summary>
        /// (Updatable) A list of destinations for alarm notifications. Each destination is represented by the OCID of a related resource, such as a topic.
        /// </summary>
        public InputList<string> Destinations
        {
            get => _destinations ?? (_destinations = new InputList<string>());
            set => _destinations = value;
        }

        /// <summary>
        /// (Updatable) A user-friendly name for the monitoring template. It is unique and mutable in nature. Avoid entering confidential information.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

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
        /// (Updatable) Whether the alarm is enabled or disabled, it will be Enabled by default.
        /// </summary>
        [Input("isAlarmsEnabled")]
        public Input<bool>? IsAlarmsEnabled { get; set; }

        /// <summary>
        /// (Updatable) Whether the alarm notification is enabled or disabled, it will be Enabled by default.
        /// </summary>
        [Input("isSplitNotificationEnabled")]
        public Input<bool>? IsSplitNotificationEnabled { get; set; }

        [Input("members")]
        private InputList<Inputs.MonitoringTemplateMemberGetArgs>? _members;

        /// <summary>
        /// (Updatable) List of members of this monitoring template
        /// </summary>
        public InputList<Inputs.MonitoringTemplateMemberGetArgs> Members
        {
            get => _members ?? (_members = new InputList<Inputs.MonitoringTemplateMemberGetArgs>());
            set => _members = value;
        }

        /// <summary>
        /// (Updatable) The format to use for alarm notifications.
        /// </summary>
        [Input("messageFormat")]
        public Input<string>? MessageFormat { get; set; }

        /// <summary>
        /// (Updatable) The frequency for re-submitting alarm notifications, if the alarm keeps firing without interruption. Format defined by ISO 8601. For example, PT4H indicates four hours. Minimum- PT1M. Maximum - P30D.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("repeatNotificationDuration")]
        public Input<string>? RepeatNotificationDuration { get; set; }

        /// <summary>
        /// The current lifecycle state of the monitoring template.
        /// </summary>
        [Input("state")]
        public Input<string>? State { get; set; }

        /// <summary>
        /// The current status of the monitoring template i.e. whether it is Applied or NotApplied.
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
        /// Tenant Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        [Input("tenantId")]
        public Input<string>? TenantId { get; set; }

        /// <summary>
        /// The date and time the monitoringTemplate was created. Format defined by RFC3339.
        /// </summary>
        [Input("timeCreated")]
        public Input<string>? TimeCreated { get; set; }

        /// <summary>
        /// The date and time the monitoringTemplate was last updated. Format defined by RFC3339.
        /// </summary>
        [Input("timeUpdated")]
        public Input<string>? TimeUpdated { get; set; }

        /// <summary>
        /// Total Alarm Conditions
        /// </summary>
        [Input("totalAlarmConditions")]
        public Input<double>? TotalAlarmConditions { get; set; }

        /// <summary>
        /// Total Applied Alarm Conditions
        /// </summary>
        [Input("totalAppliedAlarmConditions")]
        public Input<double>? TotalAppliedAlarmConditions { get; set; }

        public MonitoringTemplateState()
        {
        }
        public static new MonitoringTemplateState Empty => new MonitoringTemplateState();
    }
}
