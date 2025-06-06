// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Identity.Inputs
{

    public sealed class DomainsIdentitySettingPosixUidGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// (Updatable) The number at which the Posix Uid Manual assignment ends.
        /// 
        /// **Added In:** 17.4.6
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: integer
        /// * uniqueness: none
        /// </summary>
        [Input("manualAssignmentEndsAt")]
        public Input<int>? ManualAssignmentEndsAt { get; set; }

        /// <summary>
        /// (Updatable) The number from which the Posix Uid Manual assignment starts.
        /// 
        /// **Added In:** 17.4.6
        /// 
        /// **SCIM++ Properties:**
        /// * caseExact: false
        /// * multiValued: false
        /// * mutability: readWrite
        /// * required: false
        /// * returned: default
        /// * type: integer
        /// * uniqueness: none
        /// </summary>
        [Input("manualAssignmentStartsFrom")]
        public Input<int>? ManualAssignmentStartsFrom { get; set; }

        public DomainsIdentitySettingPosixUidGetArgs()
        {
        }
        public static new DomainsIdentitySettingPosixUidGetArgs Empty => new DomainsIdentitySettingPosixUidGetArgs();
    }
}
