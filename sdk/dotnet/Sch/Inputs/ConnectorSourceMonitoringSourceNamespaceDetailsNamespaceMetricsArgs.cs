// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Sch.Inputs
{

    public sealed class ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetricsArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The type discriminator.
        /// </summary>
        [Input("kind", required: true)]
        public Input<string> Kind { get; set; } = null!;

        public ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetricsArgs()
        {
        }
        public static new ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetricsArgs Empty => new ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetricsArgs();
    }
}
