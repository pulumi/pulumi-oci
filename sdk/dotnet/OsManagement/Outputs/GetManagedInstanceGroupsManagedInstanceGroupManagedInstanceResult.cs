// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagement.Outputs
{

    [OutputType]
    public sealed class GetManagedInstanceGroupsManagedInstanceGroupManagedInstanceResult
    {
        /// <summary>
        /// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// unique identifier that is immutable on creation
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetManagedInstanceGroupsManagedInstanceGroupManagedInstanceResult(
            string displayName,

            string id)
        {
            DisplayName = displayName;
            Id = id;
        }
    }
}
