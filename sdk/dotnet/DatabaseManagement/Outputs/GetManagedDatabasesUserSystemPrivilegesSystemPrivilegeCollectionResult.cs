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
    public sealed class GetManagedDatabasesUserSystemPrivilegesSystemPrivilegeCollectionResult
    {
        /// <summary>
        /// An array of system privileges.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedDatabasesUserSystemPrivilegesSystemPrivilegeCollectionItemResult> Items;

        [OutputConstructor]
        private GetManagedDatabasesUserSystemPrivilegesSystemPrivilegeCollectionResult(ImmutableArray<Outputs.GetManagedDatabasesUserSystemPrivilegesSystemPrivilegeCollectionItemResult> items)
        {
            Items = items;
        }
    }
}