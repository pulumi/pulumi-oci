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
    public sealed class GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionResult
    {
        public readonly ImmutableArray<Outputs.GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemResult> Items;

        [OutputConstructor]
        private GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionResult(ImmutableArray<Outputs.GetAnnouncementSubscriptionsAnnouncementSubscriptionCollectionItemResult> items)
        {
            Items = items;
        }
    }
}