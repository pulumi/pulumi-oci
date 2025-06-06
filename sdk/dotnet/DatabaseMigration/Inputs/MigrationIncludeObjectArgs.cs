// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Inputs
{

    public sealed class MigrationIncludeObjectArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Whether an excluded table should be omitted from replication. Only valid for database objects  that have are of type TABLE and object status EXCLUDE.
        /// </summary>
        [Input("isOmitExcludedTableFromReplication")]
        public Input<bool>? IsOmitExcludedTableFromReplication { get; set; }

        /// <summary>
        /// Name of the object (regular expression is allowed)
        /// </summary>
        [Input("object", required: true)]
        public Input<string> Object { get; set; } = null!;

        /// <summary>
        /// Owner of the object (regular expression is allowed)
        /// </summary>
        [Input("owner")]
        public Input<string>? Owner { get; set; }

        /// <summary>
        /// Schema of the object (regular expression is allowed)
        /// </summary>
        [Input("schema")]
        public Input<string>? Schema { get; set; }

        /// <summary>
        /// Type of object to exclude. If not specified, matching owners and object names of type TABLE would be excluded.
        /// </summary>
        [Input("type")]
        public Input<string>? Type { get; set; }

        public MigrationIncludeObjectArgs()
        {
        }
        public static new MigrationIncludeObjectArgs Empty => new MigrationIncludeObjectArgs();
    }
}
