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
    public sealed class GetManagedDatabaseUserConsumerGroupPrivilegesConsumerGroupPrivilegeCollectionItemResult
    {
        /// <summary>
        /// Indicates whether the privilege is granted with the GRANT option (YES) or not (NO).
        /// </summary>
        public readonly string GrantOption;
        /// <summary>
        /// Indicates whether the consumer group is designated as the default for this user or role (YES) or not (NO).
        /// </summary>
        public readonly string InitialGroup;
        /// <summary>
        /// A filter to return only resources that match the entire name.
        /// </summary>
        public readonly string Name;

        [OutputConstructor]
        private GetManagedDatabaseUserConsumerGroupPrivilegesConsumerGroupPrivilegeCollectionItemResult(
            string grantOption,

            string initialGroup,

            string name)
        {
            GrantOption = grantOption;
            InitialGroup = initialGroup;
            Name = name;
        }
    }
}