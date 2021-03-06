// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.ApmSynthetics
{
    public static class GetMonitor
    {
        /// <summary>
        /// This data source provides details about a specific Monitor resource in Oracle Cloud Infrastructure Apm Synthetics service.
        /// 
        /// Gets the configuration of the monitor identified by the OCID.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testMonitor = Output.Create(Oci.ApmSynthetics.GetMonitor.InvokeAsync(new Oci.ApmSynthetics.GetMonitorArgs
        ///         {
        ///             ApmDomainId = oci_apm_synthetics_apm_domain.Test_apm_domain.Id,
        ///             MonitorId = oci_apm_synthetics_monitor.Test_monitor.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetMonitorResult> InvokeAsync(GetMonitorArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetMonitorResult>("oci:ApmSynthetics/getMonitor:getMonitor", args ?? new GetMonitorArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Monitor resource in Oracle Cloud Infrastructure Apm Synthetics service.
        /// 
        /// Gets the configuration of the monitor identified by the OCID.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// class MyStack : Stack
        /// {
        ///     public MyStack()
        ///     {
        ///         var testMonitor = Output.Create(Oci.ApmSynthetics.GetMonitor.InvokeAsync(new Oci.ApmSynthetics.GetMonitorArgs
        ///         {
        ///             ApmDomainId = oci_apm_synthetics_apm_domain.Test_apm_domain.Id,
        ///             MonitorId = oci_apm_synthetics_monitor.Test_monitor.Id,
        ///         }));
        ///     }
        /// 
        /// }
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetMonitorResult> Invoke(GetMonitorInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetMonitorResult>("oci:ApmSynthetics/getMonitor:getMonitor", args ?? new GetMonitorInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetMonitorArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The APM domain ID the request is intended for.
        /// </summary>
        [Input("apmDomainId", required: true)]
        public string ApmDomainId { get; set; } = null!;

        /// <summary>
        /// The OCID of the monitor.
        /// </summary>
        [Input("monitorId", required: true)]
        public string MonitorId { get; set; } = null!;

        public GetMonitorArgs()
        {
        }
    }

    public sealed class GetMonitorInvokeArgs : Pulumi.InvokeArgs
    {
        /// <summary>
        /// The APM domain ID the request is intended for.
        /// </summary>
        [Input("apmDomainId", required: true)]
        public Input<string> ApmDomainId { get; set; } = null!;

        /// <summary>
        /// The OCID of the monitor.
        /// </summary>
        [Input("monitorId", required: true)]
        public Input<string> MonitorId { get; set; } = null!;

        public GetMonitorInvokeArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetMonitorResult
    {
        public readonly string ApmDomainId;
        /// <summary>
        /// Details of monitor configuration.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMonitorConfigurationResult> Configurations;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Unique name that can be edited. The name should not contain any confidential information.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the monitor.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// If runOnce is enabled, then the monitor will run once.
        /// </summary>
        public readonly bool IsRunOnce;
        public readonly string MonitorId;
        /// <summary>
        /// Type of the monitor.
        /// </summary>
        public readonly string MonitorType;
        /// <summary>
        /// Interval in seconds after the start time when the job should be repeated. Minimum repeatIntervalInSeconds should be 300 seconds.
        /// </summary>
        public readonly int RepeatIntervalInSeconds;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the script. scriptId is mandatory for creation of SCRIPTED_BROWSER and SCRIPTED_REST monitor types. For other monitor types, it should be set to null.
        /// </summary>
        public readonly string ScriptId;
        /// <summary>
        /// Name of the script.
        /// </summary>
        public readonly string ScriptName;
        /// <summary>
        /// List of script parameters. Example: `[{"monitorScriptParameter": {"paramName": "userid", "paramValue":"testuser"}, "isSecret": false, "isOverwritten": false}]`
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMonitorScriptParameterResult> ScriptParameters;
        /// <summary>
        /// Enables or disables the monitor.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// Specify the endpoint on which to run the monitor. For BROWSER and REST monitor types, target is mandatory. If target is specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script (specified by scriptId in monitor) against the specified target endpoint. If target is not specified in the SCRIPTED_BROWSER monitor type, then the monitor will run the selected script as it is.
        /// </summary>
        public readonly string Target;
        /// <summary>
        /// The time the resource was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The time the resource was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-13T22:47:12.613Z`
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Timeout in seconds. Timeout cannot be more than 30% of repeatIntervalInSeconds time for monitors. Also, timeoutInSeconds should be a multiple of 60. Monitor will be allowed to run only for timeoutInSeconds time. It would be terminated after that.
        /// </summary>
        public readonly int TimeoutInSeconds;
        /// <summary>
        /// Number of vantage points where monitor is running.
        /// </summary>
        public readonly int VantagePointCount;
        /// <summary>
        /// List of vantage points from where monitor is running.
        /// </summary>
        public readonly ImmutableArray<string> VantagePoints;

        [OutputConstructor]
        private GetMonitorResult(
            string apmDomainId,

            ImmutableArray<Outputs.GetMonitorConfigurationResult> configurations,

            ImmutableDictionary<string, object> definedTags,

            string displayName,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            bool isRunOnce,

            string monitorId,

            string monitorType,

            int repeatIntervalInSeconds,

            string scriptId,

            string scriptName,

            ImmutableArray<Outputs.GetMonitorScriptParameterResult> scriptParameters,

            string status,

            string target,

            string timeCreated,

            string timeUpdated,

            int timeoutInSeconds,

            int vantagePointCount,

            ImmutableArray<string> vantagePoints)
        {
            ApmDomainId = apmDomainId;
            Configurations = configurations;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            IsRunOnce = isRunOnce;
            MonitorId = monitorId;
            MonitorType = monitorType;
            RepeatIntervalInSeconds = repeatIntervalInSeconds;
            ScriptId = scriptId;
            ScriptName = scriptName;
            ScriptParameters = scriptParameters;
            Status = status;
            Target = target;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
            TimeoutInSeconds = timeoutInSeconds;
            VantagePointCount = vantagePointCount;
            VantagePoints = vantagePoints;
        }
    }
}
