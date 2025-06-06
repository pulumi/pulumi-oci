// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Outputs
{

    [OutputType]
    public sealed class GetMonitoredResourceTypesMonitoredResourceTypesCollectionItemHandlerConfigMetricNameConfigResult
    {
        /// <summary>
        /// String pattern to be removed from the prefix of the metric name.
        /// </summary>
        public readonly string ExcludePatternOnPrefix;
        /// <summary>
        /// is prefixing the metric with collector type.
        /// </summary>
        public readonly bool IsPrefixWithCollectorType;

        [OutputConstructor]
        private GetMonitoredResourceTypesMonitoredResourceTypesCollectionItemHandlerConfigMetricNameConfigResult(
            string excludePatternOnPrefix,

            bool isPrefixWithCollectorType)
        {
            ExcludePatternOnPrefix = excludePatternOnPrefix;
            IsPrefixWithCollectorType = isPrefixWithCollectorType;
        }
    }
}
