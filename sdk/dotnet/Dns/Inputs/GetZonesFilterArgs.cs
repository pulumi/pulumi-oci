// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Dns.Inputs
{

    public sealed class GetZonesFilterInputArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// A case-sensitive filter for zone names. Will match any zone with a name that equals the provided value.
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

        public GetZonesFilterInputArgs()
        {
        }
        public static new GetZonesFilterInputArgs Empty => new GetZonesFilterInputArgs();
    }
}