// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DevOps.Outputs
{

    [OutputType]
    public sealed class ProjectNotificationConfig
    {
        /// <summary>
        /// (Updatable) The topic ID for notifications.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        public readonly string TopicId;

        [OutputConstructor]
        private ProjectNotificationConfig(string topicId)
        {
            TopicId = topicId;
        }
    }
}
