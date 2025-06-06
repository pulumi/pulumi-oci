// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Inputs
{

    public sealed class UserAssessmentIgnoredTargetGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("lifecycleState")]
        public Input<string>? LifecycleState { get; set; }

        /// <summary>
        /// The OCID of the target database on which the user assessment is to be run.
        /// 
        /// 
        /// ** IMPORTANT **
        /// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        /// </summary>
        [Input("targetId")]
        public Input<string>? TargetId { get; set; }

        [Input("userAssessmentId")]
        public Input<string>? UserAssessmentId { get; set; }

        public UserAssessmentIgnoredTargetGetArgs()
        {
        }
        public static new UserAssessmentIgnoredTargetGetArgs Empty => new UserAssessmentIgnoredTargetGetArgs();
    }
}
