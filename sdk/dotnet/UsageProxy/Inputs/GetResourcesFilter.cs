// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.UsageProxy.Inputs
{

    public sealed class GetResourcesFilterArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Name of the resource.
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

        public GetResourcesFilterArgs()
        {
        }
        public static new GetResourcesFilterArgs Empty => new GetResourcesFilterArgs();
    }
}