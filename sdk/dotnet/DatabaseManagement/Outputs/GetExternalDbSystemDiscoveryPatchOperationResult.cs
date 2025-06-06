// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetExternalDbSystemDiscoveryPatchOperationResult
    {
        public readonly string Operation;
        public readonly string Selection;
        public readonly ImmutableArray<Outputs.GetExternalDbSystemDiscoveryPatchOperationValueResult> Values;

        [OutputConstructor]
        private GetExternalDbSystemDiscoveryPatchOperationResult(
            string operation,

            string selection,

            ImmutableArray<Outputs.GetExternalDbSystemDiscoveryPatchOperationValueResult> values)
        {
            Operation = operation;
            Selection = selection;
            Values = values;
        }
    }
}
