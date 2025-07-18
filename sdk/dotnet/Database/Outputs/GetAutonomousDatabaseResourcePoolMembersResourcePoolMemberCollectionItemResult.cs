// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetAutonomousDatabaseResourcePoolMembersResourcePoolMemberCollectionItemResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database.
        /// </summary>
        public readonly string Id;

        [OutputConstructor]
        private GetAutonomousDatabaseResourcePoolMembersResourcePoolMemberCollectionItemResult(string id)
        {
            Id = id;
        }
    }
}
