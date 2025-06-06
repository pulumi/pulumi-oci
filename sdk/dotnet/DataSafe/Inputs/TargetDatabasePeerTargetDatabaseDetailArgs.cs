// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Inputs
{

    public sealed class TargetDatabasePeerTargetDatabaseDetailArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Details of the database for the registration in Data Safe.
        /// </summary>
        [Input("databaseDetails", required: true)]
        public Input<Inputs.TargetDatabasePeerTargetDatabaseDetailDatabaseDetailsArgs> DatabaseDetails { get; set; } = null!;

        /// <summary>
        /// The OCID of the Data Guard Association resource in which the database being registered is considered as peer database to the primary database.
        /// </summary>
        [Input("dataguardAssociationId")]
        public Input<string>? DataguardAssociationId { get; set; }

        /// <summary>
        /// The description of the peer target database in Data Safe.
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// The display name of the peer target database in Data Safe. The name is modifiable and does not need to be unique.
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The details required to establish a TLS enabled connection.
        /// </summary>
        [Input("tlsConfig")]
        public Input<Inputs.TargetDatabasePeerTargetDatabaseDetailTlsConfigArgs>? TlsConfig { get; set; }

        public TargetDatabasePeerTargetDatabaseDetailArgs()
        {
        }
        public static new TargetDatabasePeerTargetDatabaseDetailArgs Empty => new TargetDatabasePeerTargetDatabaseDetailArgs();
    }
}
