// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AnnouncementsService.Outputs
{

    [OutputType]
    public sealed class GetServicesServicesCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetServicesServicesCollectionItemResult> Items;

        [OutputConstructor]
        private GetServicesServicesCollectionResult(ImmutableArray<Outputs.GetServicesServicesCollectionItemResult> items)
        {
            Items = items;
        }
    }
}
