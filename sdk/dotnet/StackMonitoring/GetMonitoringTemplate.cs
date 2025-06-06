// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring
{
    public static class GetMonitoringTemplate
    {
        /// <summary>
        /// This data source provides details about a specific Monitoring Template resource in Oracle Cloud Infrastructure Stack Monitoring service.
        /// 
        /// Gets a Monitoring Template by identifier
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
        ///     var testMonitoringTemplate = Oci.StackMonitoring.GetMonitoringTemplate.Invoke(new()
        ///     {
        ///         MonitoringTemplateId = testMonitoringTemplateOciStackMonitoringMonitoringTemplate.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetMonitoringTemplateResult> InvokeAsync(GetMonitoringTemplateArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetMonitoringTemplateResult>("oci:StackMonitoring/getMonitoringTemplate:getMonitoringTemplate", args ?? new GetMonitoringTemplateArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Monitoring Template resource in Oracle Cloud Infrastructure Stack Monitoring service.
        /// 
        /// Gets a Monitoring Template by identifier
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
        ///     var testMonitoringTemplate = Oci.StackMonitoring.GetMonitoringTemplate.Invoke(new()
        ///     {
        ///         MonitoringTemplateId = testMonitoringTemplateOciStackMonitoringMonitoringTemplate.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetMonitoringTemplateResult> Invoke(GetMonitoringTemplateInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetMonitoringTemplateResult>("oci:StackMonitoring/getMonitoringTemplate:getMonitoringTemplate", args ?? new GetMonitoringTemplateInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Monitoring Template resource in Oracle Cloud Infrastructure Stack Monitoring service.
        /// 
        /// Gets a Monitoring Template by identifier
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
        ///     var testMonitoringTemplate = Oci.StackMonitoring.GetMonitoringTemplate.Invoke(new()
        ///     {
        ///         MonitoringTemplateId = testMonitoringTemplateOciStackMonitoringMonitoringTemplate.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetMonitoringTemplateResult> Invoke(GetMonitoringTemplateInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetMonitoringTemplateResult>("oci:StackMonitoring/getMonitoringTemplate:getMonitoringTemplate", args ?? new GetMonitoringTemplateInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetMonitoringTemplateArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
        /// </summary>
        [Input("monitoringTemplateId", required: true)]
        public string MonitoringTemplateId { get; set; } = null!;

        public GetMonitoringTemplateArgs()
        {
        }
        public static new GetMonitoringTemplateArgs Empty => new GetMonitoringTemplateArgs();
    }

    public sealed class GetMonitoringTemplateInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitoring template.
        /// </summary>
        [Input("monitoringTemplateId", required: true)]
        public Input<string> MonitoringTemplateId { get; set; } = null!;

        public GetMonitoringTemplateInvokeArgs()
        {
        }
        public static new GetMonitoringTemplateInvokeArgs Empty => new GetMonitoringTemplateInvokeArgs();
    }


    [OutputType]
    public sealed class GetMonitoringTemplateResult
    {
        /// <summary>
        /// The OCID of the compartment containing the monitoringTemplate.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> DefinedTags;
        /// <summary>
        /// A user-friendly description for the monitoring template. It does not have to be unique, and it's changeable. Avoid entering confidential information.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A list of destinations for alarm notifications. Each destination is represented by the OCID of a related resource.
        /// </summary>
        public readonly ImmutableArray<string> Destinations;
        /// <summary>
        /// A user-friendly name for the monitoring template. It should be unique, and it's mutable in nature. Avoid entering confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> FreeformTags;
        /// <summary>
        /// The OCID of the resourceInstance/resourceType/resourceGroup
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Whether the alarm is enabled or disabled. Default value is enabled.
        /// </summary>
        public readonly bool IsAlarmsEnabled;
        /// <summary>
        /// Whether the alarm notification is enabled or disabled, it will be Enabled by default.
        /// </summary>
        public readonly bool IsSplitNotificationEnabled;
        /// <summary>
        /// List of members of this monitoring template.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMonitoringTemplateMemberResult> Members;
        /// <summary>
        /// The format to use for alarm notifications.
        /// </summary>
        public readonly string MessageFormat;
        public readonly string MonitoringTemplateId;
        /// <summary>
        /// The frequency for re-submitting alarm notifications, if the alarm keeps firing without interruption. Format defined by ISO 8601. For example, PT4H indicates four hours. Minimum- PT1M. Maximum - P30D.
        /// </summary>
        public readonly string RepeatNotificationDuration;
        /// <summary>
        /// The current lifecycle state of the monitoring template.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The current status of the monitoring template i.e. whether it is Applied or NotApplied.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        /// </summary>
        public readonly ImmutableDictionary<string, string> SystemTags;
        /// <summary>
        /// Tenant Identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)
        /// </summary>
        public readonly string TenantId;
        /// <summary>
        /// The date and time the monitoringTemplate was created. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The date and time the monitoringTemplate was last updated. Format defined by RFC3339.
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Total Alarm Conditions
        /// </summary>
        public readonly double TotalAlarmConditions;
        /// <summary>
        /// Total Applied Alarm Conditions
        /// </summary>
        public readonly double TotalAppliedAlarmConditions;

        [OutputConstructor]
        private GetMonitoringTemplateResult(
            string compartmentId,

            ImmutableDictionary<string, string> definedTags,

            string description,

            ImmutableArray<string> destinations,

            string displayName,

            ImmutableDictionary<string, string> freeformTags,

            string id,

            bool isAlarmsEnabled,

            bool isSplitNotificationEnabled,

            ImmutableArray<Outputs.GetMonitoringTemplateMemberResult> members,

            string messageFormat,

            string monitoringTemplateId,

            string repeatNotificationDuration,

            string state,

            string status,

            ImmutableDictionary<string, string> systemTags,

            string tenantId,

            string timeCreated,

            string timeUpdated,

            double totalAlarmConditions,

            double totalAppliedAlarmConditions)
        {
            CompartmentId = compartmentId;
            DefinedTags = definedTags;
            Description = description;
            Destinations = destinations;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IsAlarmsEnabled = isAlarmsEnabled;
            IsSplitNotificationEnabled = isSplitNotificationEnabled;
            Members = members;
            MessageFormat = messageFormat;
            MonitoringTemplateId = monitoringTemplateId;
            RepeatNotificationDuration = repeatNotificationDuration;
            State = state;
            Status = status;
            SystemTags = systemTags;
            TenantId = tenantId;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            TotalAlarmConditions = totalAlarmConditions;
            TotalAppliedAlarmConditions = totalAppliedAlarmConditions;
        }
    }
}
