// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Sch.Inputs
{

    public sealed class ConnectorSourceMonitoringSourceNamespaceDetailsGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The type descriminator.
        /// </summary>
        [Input("kind", required: true)]
        public Input<string> Kind { get; set; } = null!;

        [Input("namespaces", required: true)]
        private InputList<Inputs.ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceGetArgs>? _namespaces;

        /// <summary>
        /// (Updatable) The namespaces for the compartment-specific list.
        /// </summary>
        public InputList<Inputs.ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceGetArgs> Namespaces
        {
            get => _namespaces ?? (_namespaces = new InputList<Inputs.ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceGetArgs>());
            set => _namespaces = value;
        }

        public ConnectorSourceMonitoringSourceNamespaceDetailsGetArgs()
        {
        }
        public static new ConnectorSourceMonitoringSourceNamespaceDetailsGetArgs Empty => new ConnectorSourceMonitoringSourceNamespaceDetailsGetArgs();
    }
}