// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.HealthChecks
{
    public static class GetPingProbeResults
    {
        /// <summary>
        /// This data source provides the list of Ping Probe Results in Oracle Cloud Infrastructure Health Checks service.
        /// 
        /// Returns the results for the specified probe, where the `probeConfigurationId`
        /// is the OCID of either a monitor or an on-demand probe.
        /// 
        /// Results are paginated based on `page` and `limit`.  The `opc-next-page` header provides
        /// a URL for fetching the next page.  Use `sortOrder` to set the order of the
        /// results.  If `sortOrder` is unspecified, results are sorted in ascending order by
        /// `startTime`.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testPingProbeResults = Oci.HealthChecks.GetPingProbeResults.Invoke(new()
        ///     {
        ///         ProbeConfigurationId = oci_health_checks_probe_configuration.Test_probe_configuration.Id,
        ///         StartTimeGreaterThanOrEqualTo = @var.Ping_probe_result_start_time_greater_than_or_equal_to,
        ///         StartTimeLessThanOrEqualTo = @var.Ping_probe_result_start_time_less_than_or_equal_to,
        ///         Target = @var.Ping_probe_result_target,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetPingProbeResultsResult> InvokeAsync(GetPingProbeResultsArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetPingProbeResultsResult>("oci:HealthChecks/getPingProbeResults:getPingProbeResults", args ?? new GetPingProbeResultsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Ping Probe Results in Oracle Cloud Infrastructure Health Checks service.
        /// 
        /// Returns the results for the specified probe, where the `probeConfigurationId`
        /// is the OCID of either a monitor or an on-demand probe.
        /// 
        /// Results are paginated based on `page` and `limit`.  The `opc-next-page` header provides
        /// a URL for fetching the next page.  Use `sortOrder` to set the order of the
        /// results.  If `sortOrder` is unspecified, results are sorted in ascending order by
        /// `startTime`.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testPingProbeResults = Oci.HealthChecks.GetPingProbeResults.Invoke(new()
        ///     {
        ///         ProbeConfigurationId = oci_health_checks_probe_configuration.Test_probe_configuration.Id,
        ///         StartTimeGreaterThanOrEqualTo = @var.Ping_probe_result_start_time_greater_than_or_equal_to,
        ///         StartTimeLessThanOrEqualTo = @var.Ping_probe_result_start_time_less_than_or_equal_to,
        ///         Target = @var.Ping_probe_result_target,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetPingProbeResultsResult> Invoke(GetPingProbeResultsInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetPingProbeResultsResult>("oci:HealthChecks/getPingProbeResults:getPingProbeResults", args ?? new GetPingProbeResultsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetPingProbeResultsArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private List<Inputs.GetPingProbeResultsFilterArgs>? _filters;
        public List<Inputs.GetPingProbeResultsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetPingProbeResultsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of a monitor or on-demand probe.
        /// </summary>
        [Input("probeConfigurationId", required: true)]
        public string ProbeConfigurationId { get; set; } = null!;

        /// <summary>
        /// Returns results with a `startTime` equal to or greater than the specified value.
        /// </summary>
        [Input("startTimeGreaterThanOrEqualTo")]
        public double? StartTimeGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// Returns results with a `startTime` equal to or less than the specified value.
        /// </summary>
        [Input("startTimeLessThanOrEqualTo")]
        public double? StartTimeLessThanOrEqualTo { get; set; }

        /// <summary>
        /// Filters results that match the `target`.
        /// </summary>
        [Input("target")]
        public string? Target { get; set; }

        public GetPingProbeResultsArgs()
        {
        }
        public static new GetPingProbeResultsArgs Empty => new GetPingProbeResultsArgs();
    }

    public sealed class GetPingProbeResultsInvokeArgs : global::Pulumi.InvokeArgs
    {
        [Input("filters")]
        private InputList<Inputs.GetPingProbeResultsFilterInputArgs>? _filters;
        public InputList<Inputs.GetPingProbeResultsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetPingProbeResultsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// The OCID of a monitor or on-demand probe.
        /// </summary>
        [Input("probeConfigurationId", required: true)]
        public Input<string> ProbeConfigurationId { get; set; } = null!;

        /// <summary>
        /// Returns results with a `startTime` equal to or greater than the specified value.
        /// </summary>
        [Input("startTimeGreaterThanOrEqualTo")]
        public Input<double>? StartTimeGreaterThanOrEqualTo { get; set; }

        /// <summary>
        /// Returns results with a `startTime` equal to or less than the specified value.
        /// </summary>
        [Input("startTimeLessThanOrEqualTo")]
        public Input<double>? StartTimeLessThanOrEqualTo { get; set; }

        /// <summary>
        /// Filters results that match the `target`.
        /// </summary>
        [Input("target")]
        public Input<string>? Target { get; set; }

        public GetPingProbeResultsInvokeArgs()
        {
        }
        public static new GetPingProbeResultsInvokeArgs Empty => new GetPingProbeResultsInvokeArgs();
    }


    [OutputType]
    public sealed class GetPingProbeResultsResult
    {
        public readonly ImmutableArray<Outputs.GetPingProbeResultsFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of ping_probe_results.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPingProbeResultsPingProbeResultResult> PingProbeResults;
        /// <summary>
        /// The OCID of the monitor or on-demand probe responsible for creating this result.
        /// </summary>
        public readonly string ProbeConfigurationId;
        public readonly double? StartTimeGreaterThanOrEqualTo;
        public readonly double? StartTimeLessThanOrEqualTo;
        /// <summary>
        /// The target hostname or IP address of the probe.
        /// </summary>
        public readonly string? Target;

        [OutputConstructor]
        private GetPingProbeResultsResult(
            ImmutableArray<Outputs.GetPingProbeResultsFilterResult> filters,

            string id,

            ImmutableArray<Outputs.GetPingProbeResultsPingProbeResultResult> pingProbeResults,

            string probeConfigurationId,

            double? startTimeGreaterThanOrEqualTo,

            double? startTimeLessThanOrEqualTo,

            string? target)
        {
            Filters = filters;
            Id = id;
            PingProbeResults = pingProbeResults;
            ProbeConfigurationId = probeConfigurationId;
            StartTimeGreaterThanOrEqualTo = startTimeGreaterThanOrEqualTo;
            StartTimeLessThanOrEqualTo = startTimeLessThanOrEqualTo;
            Target = target;
        }
    }
}