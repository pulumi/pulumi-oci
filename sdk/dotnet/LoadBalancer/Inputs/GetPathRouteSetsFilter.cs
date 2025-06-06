// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.LoadBalancer.Inputs
{

    public sealed class GetPathRouteSetsFilterArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The unique name for this set of path route rules. Avoid entering confidential information.  Example: `example_path_route_set`
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

        public GetPathRouteSetsFilterArgs()
        {
        }
        public static new GetPathRouteSetsFilterArgs Empty => new GetPathRouteSetsFilterArgs();
    }
}
