// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Inputs
{

    public sealed class MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Resource name generation overriding configurations for collectd resource types.
        /// </summary>
        [Input("collectdResourceNameConfig")]
        public Input<Inputs.MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigCollectdResourceNameConfigArgs>? CollectdResourceNameConfig { get; set; }

        [Input("collectorTypes")]
        private InputList<string>? _collectorTypes;

        /// <summary>
        /// List of collector/plugin names.
        /// </summary>
        public InputList<string> CollectorTypes
        {
            get => _collectorTypes ?? (_collectorTypes = new InputList<string>());
            set => _collectorTypes = value;
        }

        [Input("handlerProperties")]
        private InputList<Inputs.MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyArgs>? _handlerProperties;

        /// <summary>
        /// List of handler configuration properties
        /// </summary>
        public InputList<Inputs.MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyArgs> HandlerProperties
        {
            get => _handlerProperties ?? (_handlerProperties = new InputList<Inputs.MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigHandlerPropertyArgs>());
            set => _handlerProperties = value;
        }

        [Input("metricMappings")]
        private InputList<Inputs.MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigMetricMappingArgs>? _metricMappings;

        /// <summary>
        /// List of AgentExtensionHandlerMetricMappingDetails.
        /// </summary>
        public InputList<Inputs.MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigMetricMappingArgs> MetricMappings
        {
            get => _metricMappings ?? (_metricMappings = new InputList<Inputs.MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigMetricMappingArgs>());
            set => _metricMappings = value;
        }

        /// <summary>
        /// Metric name generation overriding configurations.
        /// </summary>
        [Input("metricNameConfig")]
        public Input<Inputs.MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigMetricNameConfigArgs>? MetricNameConfig { get; set; }

        /// <summary>
        /// Metric upload interval in seconds. Any metric sent by telegraf/collectd before the  configured interval expires will be dropped.
        /// </summary>
        [Input("metricUploadIntervalInSeconds")]
        public Input<int>? MetricUploadIntervalInSeconds { get; set; }

        /// <summary>
        /// Resource name generation overriding configurations for telegraf resource types.
        /// </summary>
        [Input("telegrafResourceNameConfig")]
        public Input<Inputs.MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigTelegrafResourceNameConfigArgs>? TelegrafResourceNameConfig { get; set; }

        /// <summary>
        /// Resource group string; if not specified, the resource group string will be generated by the handler.
        /// </summary>
        [Input("telemetryResourceGroup")]
        public Input<string>? TelemetryResourceGroup { get; set; }

        public MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigArgs()
        {
        }
        public static new MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigArgs Empty => new MonitoredResourceTaskTaskDetailsResourceTypesConfigurationHandlerConfigArgs();
    }
}
