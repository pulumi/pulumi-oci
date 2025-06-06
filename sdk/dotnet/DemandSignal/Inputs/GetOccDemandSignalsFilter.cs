// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DemandSignal.Inputs
{

    public sealed class GetOccDemandSignalsFilterArgs : global::Pulumi.InvokeArgs
    {
        [Input("name", required: true)]
        public string Name { get; set; } = null!;

        [Input("regex")]
        public bool? Regex { get; set; }

        [Input("values", required: true)]
        private List<string>? _values;

        /// <summary>
        /// The values of forecast.
        /// </summary>
        public List<string> Values
        {
            get => _values ?? (_values = new List<string>());
            set => _values = value;
        }

        public GetOccDemandSignalsFilterArgs()
        {
        }
        public static new GetOccDemandSignalsFilterArgs Empty => new GetOccDemandSignalsFilterArgs();
    }
}
