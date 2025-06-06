// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Inputs
{

    public sealed class MonitoredResourceTypeHandlerConfigMetricMappingGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Metric name as defined by the collector.
        /// </summary>
        [Input("collectorMetricName")]
        public Input<string>? CollectorMetricName { get; set; }

        /// <summary>
        /// Is ignoring this metric.
        /// </summary>
        [Input("isSkipUpload")]
        public Input<bool>? IsSkipUpload { get; set; }

        /// <summary>
        /// Metric upload interval in seconds. Any metric sent by telegraf/collectd before the  configured interval expires will be dropped.
        /// </summary>
        [Input("metricUploadIntervalInSeconds")]
        public Input<int>? MetricUploadIntervalInSeconds { get; set; }

        /// <summary>
        /// Metric name to be upload to telemetry.
        /// </summary>
        [Input("telemetryMetricName")]
        public Input<string>? TelemetryMetricName { get; set; }

        public MonitoredResourceTypeHandlerConfigMetricMappingGetArgs()
        {
        }
        public static new MonitoredResourceTypeHandlerConfigMetricMappingGetArgs Empty => new MonitoredResourceTypeHandlerConfigMetricMappingGetArgs();
    }
}
