// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Functions.Inputs
{

    public sealed class GetPbfListingVersionsFilterArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// Matches a PbfListingVersion based on a provided semantic version name for a PbfListingVersion.  Each PbfListingVersion name is unique with respect to its associated PbfListing.
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

        public GetPbfListingVersionsFilterArgs()
        {
        }
        public static new GetPbfListingVersionsFilterArgs Empty => new GetPbfListingVersionsFilterArgs();
    }
}