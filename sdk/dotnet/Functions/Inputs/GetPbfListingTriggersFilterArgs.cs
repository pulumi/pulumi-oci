// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Functions.Inputs
{

    public sealed class GetPbfListingTriggersFilterInputArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// A filter to return only resources that match the service trigger source of a PBF.
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

        public GetPbfListingTriggersFilterInputArgs()
        {
        }
        public static new GetPbfListingTriggersFilterInputArgs Empty => new GetPbfListingTriggersFilterInputArgs();
    }
}
