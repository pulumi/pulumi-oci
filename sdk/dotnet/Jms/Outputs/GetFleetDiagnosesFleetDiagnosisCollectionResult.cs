// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms.Outputs
{

    [OutputType]
    public sealed class GetFleetDiagnosesFleetDiagnosisCollectionResult
    {
        /// <summary>
        /// A list of the fleet resource diagnosis.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetFleetDiagnosesFleetDiagnosisCollectionItemResult> Items;

        [OutputConstructor]
        private GetFleetDiagnosesFleetDiagnosisCollectionResult(ImmutableArray<Outputs.GetFleetDiagnosesFleetDiagnosisCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
