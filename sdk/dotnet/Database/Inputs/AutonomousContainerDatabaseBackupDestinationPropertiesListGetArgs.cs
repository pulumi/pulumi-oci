// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Inputs
{

    public sealed class AutonomousContainerDatabaseBackupDestinationPropertiesListGetArgs : global::Pulumi.ResourceArgs
    {
        [Input("backupDestinationAttachHistories")]
        private InputList<string>? _backupDestinationAttachHistories;

        /// <summary>
        /// The timestamps at which this backup destination is used as the preferred destination to host the Autonomous Container Database backups.
        /// </summary>
        public InputList<string> BackupDestinationAttachHistories
        {
            get => _backupDestinationAttachHistories ?? (_backupDestinationAttachHistories = new InputList<string>());
            set => _backupDestinationAttachHistories = value;
        }

        /// <summary>
        /// The total space utilized (in GBs) by this Autonomous Container Database on this backup destination, rounded to the nearest integer.
        /// </summary>
        [Input("spaceUtilizedInGbs")]
        public Input<int>? SpaceUtilizedInGbs { get; set; }

        /// <summary>
        /// The latest timestamp when the backup destination details, such as 'spaceUtilized,' are updated.
        /// </summary>
        [Input("timeAtWhichStorageDetailsAreUpdated")]
        public Input<string>? TimeAtWhichStorageDetailsAreUpdated { get; set; }

        public AutonomousContainerDatabaseBackupDestinationPropertiesListGetArgs()
        {
        }
        public static new AutonomousContainerDatabaseBackupDestinationPropertiesListGetArgs Empty => new AutonomousContainerDatabaseBackupDestinationPropertiesListGetArgs();
    }
}
