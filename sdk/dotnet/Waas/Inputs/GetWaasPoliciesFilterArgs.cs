// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Waas.Inputs
{

    public sealed class GetWaasPoliciesFilterInputArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The unique name of the whitelist.
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

        public GetWaasPoliciesFilterInputArgs()
        {
        }
        public static new GetWaasPoliciesFilterInputArgs Empty => new GetWaasPoliciesFilterInputArgs();
    }
}
