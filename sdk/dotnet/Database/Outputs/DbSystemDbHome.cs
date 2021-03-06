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
    public sealed class DbSystemDbHome
    {
        public readonly bool? CreateAsync;
        /// <summary>
        /// (Updatable) Details for creating a database by restoring from a source database system.
        /// </summary>
        public readonly Outputs.DbSystemDbHomeDatabase Database;
        /// <summary>
        /// The database software image [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the image to be used to restore a database.
        /// </summary>
        public readonly string? DatabaseSoftwareImageId;
        public readonly string? DbHomeLocation;
        /// <summary>
        /// A valid Oracle Database version. To get a list of supported versions, use the [ListDbVersions](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/DbVersionSummary/ListDbVersions) operation.
        /// </summary>
        public readonly string? DbVersion;
        /// <summary>
        /// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
        /// </summary>
        public readonly ImmutableDictionary<string, object>? DefinedTags;
        /// <summary>
        /// The user-friendly name for the DB system. The name does not have to be unique.
        /// </summary>
        public readonly string? DisplayName;
        /// <summary>
        /// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        /// </summary>
        public readonly ImmutableDictionary<string, object>? FreeformTags;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
        /// </summary>
        public readonly string? Id;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the last patch history. This value is updated as soon as a patch operation starts.
        /// </summary>
        public readonly string? LastPatchHistoryEntryId;
        /// <summary>
        /// Additional information about the current lifecycle state.
        /// </summary>
        public readonly string? LifecycleDetails;
        /// <summary>
        /// The current state of the DB system.
        /// </summary>
        public readonly string? State;
        /// <summary>
        /// The date and time the DB system was created.
        /// </summary>
        public readonly string? TimeCreated;

        [OutputConstructor]
        private DbSystemDbHome(
            bool? createAsync,

            Outputs.DbSystemDbHomeDatabase database,

            string? databaseSoftwareImageId,

            string? dbHomeLocation,

            string? dbVersion,

            ImmutableDictionary<string, object>? definedTags,

            string? displayName,

            ImmutableDictionary<string, object>? freeformTags,

            string? id,

            string? lastPatchHistoryEntryId,

            string? lifecycleDetails,

            string? state,

            string? timeCreated)
        {
            CreateAsync = createAsync;
            Database = database;
            DatabaseSoftwareImageId = databaseSoftwareImageId;
            DbHomeLocation = dbHomeLocation;
            DbVersion = dbVersion;
            DefinedTags = definedTags;
            DisplayName = displayName;
            FreeformTags = freeformTags;
            Id = id;
            LastPatchHistoryEntryId = lastPatchHistoryEntryId;
            LifecycleDetails = lifecycleDetails;
            State = state;
            TimeCreated = timeCreated;
        }
    }
}
