// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Sch.Inputs
{

    public sealed class ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetricsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The type discriminator.
        /// </summary>
        [Input("kind", required: true)]
        public Input<string> Kind { get; set; } = null!;

        public ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetricsGetArgs()
        {
        }
        public static new ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetricsGetArgs Empty => new ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetricsGetArgs();
    }
}
