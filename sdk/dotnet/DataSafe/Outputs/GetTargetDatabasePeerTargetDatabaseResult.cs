// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DataSafe.Outputs
{

    [OutputType]
    public sealed class GetTargetDatabasePeerTargetDatabaseResult
    {
        /// <summary>
        /// Details of the database for the registration in Data Safe.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTargetDatabasePeerTargetDatabaseDatabaseDetailResult> DatabaseDetails;
        /// <summary>
        /// Unique name of the database associated to the peer target database.
        /// </summary>
        public readonly string DatabaseUniqueName;
        /// <summary>
        /// The OCID of the Data Guard Association resource in which the database associated to the peer target database is considered as peer database to the primary database.
        /// </summary>
        public readonly string DataguardAssociationId;
        /// <summary>
        /// The description of the peer target database in Data Safe.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// The display name of the peer target database in Data Safe.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// The secondary key assigned for the peer target database in Data Safe.
        /// </summary>
        public readonly int Key;
        /// <summary>
        /// Details about the current state of the peer target database in Data Safe.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// Role of the database associated to the peer target database.
        /// </summary>
        public readonly string Role;
        /// <summary>
        /// The current state of the target database in Data Safe.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time the database was registered in Data Safe and created as a target database in Data Safe.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// The details required to establish a TLS enabled connection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetTargetDatabasePeerTargetDatabaseTlsConfigResult> TlsConfigs;

        [OutputConstructor]
        private GetTargetDatabasePeerTargetDatabaseResult(
            ImmutableArray<Outputs.GetTargetDatabasePeerTargetDatabaseDatabaseDetailResult> databaseDetails,

            string databaseUniqueName,

            string dataguardAssociationId,

            string description,

            string displayName,

            int key,

            string lifecycleDetails,

            string role,

            string state,

            string timeCreated,

            ImmutableArray<Outputs.GetTargetDatabasePeerTargetDatabaseTlsConfigResult> tlsConfigs)
        {
            DatabaseDetails = databaseDetails;
            DatabaseUniqueName = databaseUniqueName;
            DataguardAssociationId = dataguardAssociationId;
            Description = description;
            DisplayName = displayName;
            Key = key;
            LifecycleDetails = lifecycleDetails;
            Role = role;
            State = state;
            TimeCreated = timeCreated;
            TlsConfigs = tlsConfigs;
        }
    }
}
