// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub.Outputs
{

    [OutputType]
    public sealed class GetSoftwarePackagesSoftwarePackageCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetSoftwarePackagesSoftwarePackageCollectionItemResult> Items;

        [OutputConstructor]
        private GetSoftwarePackagesSoftwarePackageCollectionResult(ImmutableArray<Outputs.GetSoftwarePackagesSoftwarePackageCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
