// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.AnnouncementsService.Inputs
{

    public sealed class AnnouncementSubscriptionFilterGroupsFilterArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The type of filter. You cannot combine the RESOURCE_ID filter with any other type of filter within a given filter group. For filter types that support multiple values, specify the values individually.
        /// </summary>
        [Input("type", required: true)]
        public Input<string> Type { get; set; } = null!;

        /// <summary>
        /// The value of the filter.
        /// </summary>
        [Input("value", required: true)]
        public Input<string> Value { get; set; } = null!;

        public AnnouncementSubscriptionFilterGroupsFilterArgs()
        {
        }
        public static new AnnouncementSubscriptionFilterGroupsFilterArgs Empty => new AnnouncementSubscriptionFilterGroupsFilterArgs();
    }
}
