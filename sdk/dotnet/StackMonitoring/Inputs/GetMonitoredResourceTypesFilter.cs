// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.StackMonitoring.Inputs
{

    public sealed class GetMonitoredResourceTypesFilterArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// A filter to return monitored resource types that match exactly with the resource type name given.
        /// </summary>
        [Input("name", required: true)]
        public string Name { get; set; } = null!;

        [Input("regex")]
        public bool? Regex { get; set; }

        [Input("values", required: true)]
        private List<string>? _values;
        public List<string> Values
        {
            get => _values ?? (_values = new List<string>());
            set => _values = value;
        }

        public GetMonitoredResourceTypesFilterArgs()
        {
        }
        public static new GetMonitoredResourceTypesFilterArgs Empty => new GetMonitoredResourceTypesFilterArgs();
    }
}