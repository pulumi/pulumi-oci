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
    public sealed class GetManagedInstanceGroupsManagedInstanceGroupCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetManagedInstanceGroupsManagedInstanceGroupCollectionItemResult> Items;

        [OutputConstructor]
        private GetManagedInstanceGroupsManagedInstanceGroupCollectionResult(ImmutableArray<Outputs.GetManagedInstanceGroupsManagedInstanceGroupCollectionItemResult> items)
        {
            Items = items;
        }
    }
}