// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Inputs
{

    public sealed class GetPathRouteSetsFilterInputArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The unique name for this set of path route rules. Avoid entering confidential information.  Example: `example_path_route_set`
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

        public GetPathRouteSetsFilterInputArgs()
        {
        }
        public static new GetPathRouteSetsFilterInputArgs Empty => new GetPathRouteSetsFilterInputArgs();
    }
}