// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class GetPluggableDatabasesPluggableDatabaseResult
    {
        /// <summary>
        /// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Connection strings to connect to an Oracle Pluggable Database.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetPluggableDatabasesPluggableDatabaseConnectionStringResult> ConnectionStrings;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the CDB.
        /// </summary>
        public readonly string ContainerDatabaseId;
        /// <summary>
        /// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, object> DefinedTags;
        /// <summary>
        /// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object> FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the pluggable database.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The restricted mode of the pluggable database. If a pluggable database is opened in restricted mode, the user needs both create a session and have restricted session privileges to connect to it.
        /// </summary>
        public readonly bool IsRestricted;
        /// <summary>
        /// Detailed message for the lifecycle state.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// The mode that pluggable database is in. Open mode can only be changed to READ_ONLY or MIGRATE directly from the backend (within the Oracle Database software).
        /// </summary>
        public readonly string OpenMode;
        public readonly string PdbAdminPassword;
        /// <summary>
        /// A filter to return only pluggable databases that match the entire name given. The match is not case sensitive.
        /// </summary>
        public readonly string PdbName;
        public readonly bool ShouldPdbAdminAccountBeLocked;
        /// <summary>
        /// A filter to return only resources that match the given lifecycle state exactly.
        /// </summary>
        public readonly string State;
        public readonly string TdeWalletPassword;
        /// <summary>
        /// The date and time the pluggable database was created.
        /// </summary>
        public readonly string TimeCreated;

        [OutputConstructor]
        private GetPluggableDatabasesPluggableDatabaseResult(
            string compartmentId,

            ImmutableArray<Outputs.GetPluggableDatabasesPluggableDatabaseConnectionStringResult> connectionStrings,

            string containerDatabaseId,

            ImmutableDictionary<string, object> definedTags,

            ImmutableDictionary<string, object> freeformTags,

            string id,

            bool isRestricted,

            string lifecycleDetails,

            string openMode,

            string pdbAdminPassword,

            string pdbName,

            bool shouldPdbAdminAccountBeLocked,

            string state,

            string tdeWalletPassword,

            string timeCreated)
        {
            CompartmentId = compartmentId;
            ConnectionStrings = connectionStrings;
            ContainerDatabaseId = containerDatabaseId;
            DefinedTags = definedTags;
            FreeformTags = freeformTags;
            Id = id;
            IsRestricted = isRestricted;
            LifecycleDetails = lifecycleDetails;
            OpenMode = openMode;
            PdbAdminPassword = pdbAdminPassword;
            PdbName = pdbName;
            ShouldPdbAdminAccountBeLocked = shouldPdbAdminAccountBeLocked;
            State = state;
            TdeWalletPassword = tdeWalletPassword;
            TimeCreated = timeCreated;
        }
    }
}