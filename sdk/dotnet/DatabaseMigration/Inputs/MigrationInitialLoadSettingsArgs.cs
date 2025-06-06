// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.DatabaseMigration.Inputs
{

    public sealed class MigrationInitialLoadSettingsArgs : global::Pulumi.ResourceArgs
    {
        [Input("compatibilities")]
        private InputList<string>? _compatibilities;

        /// <summary>
        /// (Updatable) Apply the specified requirements for compatibility with MySQL Database Service for all tables in the dump  output, altering the dump files as necessary.
        /// </summary>
        public InputList<string> Compatibilities
        {
            get => _compatibilities ?? (_compatibilities = new InputList<string>());
            set => _compatibilities = value;
        }

        /// <summary>
        /// (Updatable) Optional parameters for Data Pump Export and Import.
        /// </summary>
        [Input("dataPumpParameters")]
        public Input<Inputs.MigrationInitialLoadSettingsDataPumpParametersArgs>? DataPumpParameters { get; set; }

        /// <summary>
        /// (Updatable) Directory object details, used to define either import or export directory objects in Data Pump Settings. Import directory is required for Non-Autonomous target connections. If specified for an autonomous target, it will show an error. Export directory will error if there are database link details specified.
        /// </summary>
        [Input("exportDirectoryObject")]
        public Input<Inputs.MigrationInitialLoadSettingsExportDirectoryObjectArgs>? ExportDirectoryObject { get; set; }

        /// <summary>
        /// (Updatable) The action taken in the event of errors related to GRANT or REVOKE errors.
        /// </summary>
        [Input("handleGrantErrors")]
        public Input<string>? HandleGrantErrors { get; set; }

        /// <summary>
        /// (Updatable) Directory object details, used to define either import or export directory objects in Data Pump Settings. Import directory is required for Non-Autonomous target connections. If specified for an autonomous target, it will show an error. Export directory will error if there are database link details specified.
        /// </summary>
        [Input("importDirectoryObject")]
        public Input<Inputs.MigrationInitialLoadSettingsImportDirectoryObjectArgs>? ImportDirectoryObject { get; set; }

        /// <summary>
        /// (Updatable) Enable (true) or disable (false) consistent data dumps by locking the instance for backup during the dump.
        /// </summary>
        [Input("isConsistent")]
        public Input<bool>? IsConsistent { get; set; }

        /// <summary>
        /// (Updatable) Import the dump even if it contains objects that already exist in the target schema in the MySQL instance.
        /// </summary>
        [Input("isIgnoreExistingObjects")]
        public Input<bool>? IsIgnoreExistingObjects { get; set; }

        /// <summary>
        /// (Updatable) Include a statement at the start of the dump to set the time zone to UTC.
        /// </summary>
        [Input("isTzUtc")]
        public Input<bool>? IsTzUtc { get; set; }

        /// <summary>
        /// (Updatable) Oracle Job Mode
        /// </summary>
        [Input("jobMode", required: true)]
        public Input<string> JobMode { get; set; } = null!;

        [Input("metadataRemaps")]
        private InputList<Inputs.MigrationInitialLoadSettingsMetadataRemapArgs>? _metadataRemaps;

        /// <summary>
        /// (Updatable) Defines remapping to be applied to objects as they are processed.
        /// </summary>
        public InputList<Inputs.MigrationInitialLoadSettingsMetadataRemapArgs> MetadataRemaps
        {
            get => _metadataRemaps ?? (_metadataRemaps = new InputList<Inputs.MigrationInitialLoadSettingsMetadataRemapArgs>());
            set => _metadataRemaps = value;
        }

        /// <summary>
        /// (Updatable) Primary key compatibility option
        /// </summary>
        [Input("primaryKeyCompatibility")]
        public Input<string>? PrimaryKeyCompatibility { get; set; }

        /// <summary>
        /// (Updatable) Migration tablespace settings.
        /// </summary>
        [Input("tablespaceDetails")]
        public Input<Inputs.MigrationInitialLoadSettingsTablespaceDetailsArgs>? TablespaceDetails { get; set; }

        public MigrationInitialLoadSettingsArgs()
        {
        }
        public static new MigrationInitialLoadSettingsArgs Empty => new MigrationInitialLoadSettingsArgs();
    }
}
