// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseManagement.Outputs
{

    [OutputType]
    public sealed class GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollectionItemPatchOperationResult
    {
        public readonly string Operation;
        public readonly string Selection;
        public readonly ImmutableArray<Outputs.GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollectionItemPatchOperationValueResult> Values;

        [OutputConstructor]
        private GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollectionItemPatchOperationResult(
            string operation,

            string selection,

            ImmutableArray<Outputs.GetExternalDbSystemDiscoveriesExternalDbSystemDiscoveryCollectionItemPatchOperationValueResult> values)
        {
            Operation = operation;
            Selection = selection;
            Values = values;
        }
    }
}