// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.HealthChecks
{
    public static class GetPingMonitors
    {
        /// <summary>
        /// This data source provides the list of Ping Monitors in Oracle Cloud Infrastructure Health Checks service.
        /// 
        /// Gets a list of configured ping monitors.
        /// 
        /// Results are paginated based on `page` and `limit`.  The `opc-next-page` header provides
        /// a URL for fetching the next page.
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
        ///     var testPingMonitors = Oci.HealthChecks.GetPingMonitors.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = pingMonitorDisplayName,
        ///         HomeRegion = pingMonitorHomeRegion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Task<GetPingMonitorsResult> InvokeAsync(GetPingMonitorsArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetPingMonitorsResult>("oci:HealthChecks/getPingMonitors:getPingMonitors", args ?? new GetPingMonitorsArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Ping Monitors in Oracle Cloud Infrastructure Health Checks service.
        /// 
        /// Gets a list of configured ping monitors.
        /// 
        /// Results are paginated based on `page` and `limit`.  The `opc-next-page` header provides
        /// a URL for fetching the next page.
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
        ///     var testPingMonitors = Oci.HealthChecks.GetPingMonitors.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = pingMonitorDisplayName,
        ///         HomeRegion = pingMonitorHomeRegion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPingMonitorsResult> Invoke(GetPingMonitorsInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetPingMonitorsResult>("oci:HealthChecks/getPingMonitors:getPingMonitors", args ?? new GetPingMonitorsInvokeArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Ping Monitors in Oracle Cloud Infrastructure Health Checks service.
        /// 
        /// Gets a list of configured ping monitors.
        /// 
        /// Results are paginated based on `page` and `limit`.  The `opc-next-page` header provides
        /// a URL for fetching the next page.
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
        ///     var testPingMonitors = Oci.HealthChecks.GetPingMonitors.Invoke(new()
        ///     {
        ///         CompartmentId = compartmentId,
        ///         DisplayName = pingMonitorDisplayName,
        ///         HomeRegion = pingMonitorHomeRegion,
        ///     });
        /// 
        /// });
        /// ```
        /// </summary>
        public static Output<GetPingMonitorsResult> Invoke(GetPingMonitorsInvokeArgs args, InvokeOutputOptions options)
            => global::Pulumi.Deployment.Instance.Invoke<GetPingMonitorsResult>("oci:HealthChecks/getPingMonitors:getPingMonitors", args ?? new GetPingMonitorsInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetPingMonitorsArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Filters results by compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public string CompartmentId { get; set; } = null!;

        /// <summary>
        /// Filters results that exactly match the `displayName` field.
        /// </summary>
        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("filters")]
        private List<Inputs.GetPingMonitorsFilterArgs>? _filters;
        public List<Inputs.GetPingMonitorsFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetPingMonitorsFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Filters results that match the `homeRegion`.
        /// </summary>
        [Input("homeRegion")]
        public string? HomeRegion { get; set; }

        public GetPingMonitorsArgs()
        {
        }
        public static new GetPingMonitorsArgs Empty => new GetPingMonitorsArgs();
    }

    public sealed class GetPingMonitorsInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Filters results by compartment.
        /// </summary>
        [Input("compartmentId", required: true)]
        public Input<string> CompartmentId { get; set; } = null!;

        /// <summary>
        /// Filters results that exactly match the `displayName` field.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetPingMonitorsFilterInputArgs>? _filters;
        public InputList<Inputs.GetPingMonitorsFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetPingMonitorsFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Filters results that match the `homeRegion`.
        /// </summary>
        [Input("homeRegion")]
        public Input<string>? HomeRegion { get; set; }

        public GetPingMonitorsInvokeArgs()
        {
        }
        public static new GetPingMonitorsInvokeArgs Empty => new GetPingMonitorsInvokeArgs();
    }


    [OutputType]
    public sealed class GetPingMonitorsResult
    {
        /// <summary>
        /// The OCID of the compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// A user-friendly and mutable name suitable for display in a user interface.
        /// </summary>
        public readonly string? DisplayName;
        public readonly ImmutableArray<Outputs.GetPingMonitorsFilterResult> Filters;
        /// <summary>
        /// The region where updates must be made and where results must be fetched from.
        /// </summary>
        public readonly string? HomeRegion;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The list of ping_monitors.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPingMonitorsPingMonitorResult> PingMonitors;

        [OutputConstructor]
        private GetPingMonitorsResult(
            string compartmentId,

            string? displayName,

            ImmutableArray<Outputs.GetPingMonitorsFilterResult> filters,

            string? homeRegion,

            string id,

            ImmutableArray<Outputs.GetPingMonitorsPingMonitorResult> pingMonitors)
        {
            CompartmentId = compartmentId;
            DisplayName = displayName;
            Filters = filters;
            HomeRegion = homeRegion;
            Id = id;
            PingMonitors = pingMonitors;
        }
    }
}
