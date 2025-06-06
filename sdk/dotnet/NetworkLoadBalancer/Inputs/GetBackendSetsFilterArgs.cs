// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.NetworkLoadBalancer.Inputs
{

    public sealed class GetBackendSetsFilterInputArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// A user-friendly name for the backend set that must be unique and cannot be changed.
        /// </summary>
        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        [Input("regex")]
        public Input<bool>? Regex { get; set; }

        [Input("values", required: true)]
        private InputList<string>? _values;
        public InputList<string> Values
        {
            get => _values ?? (_values = new InputList<string>());
            set => _values = value;
        }

        public GetBackendSetsFilterInputArgs()
        {
        }
        public static new GetBackendSetsFilterInputArgs Empty => new GetBackendSetsFilterInputArgs();
    }
}
