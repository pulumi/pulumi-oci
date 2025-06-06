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
    public sealed class GetAutonomousContainerDatabaseDataguardAssociationsAutonomousContainerDatabaseDataguardAssociationPeerAutonomousContainerDatabaseBackupConfigResult
    {
        public readonly ImmutableArray<Outputs.GetAutonomousContainerDatabaseDataguardAssociationsAutonomousContainerDatabaseDataguardAssociationPeerAutonomousContainerDatabaseBackupConfigBackupDestinationDetailResult> BackupDestinationDetails;
        public readonly int RecoveryWindowInDays;

        [OutputConstructor]
        private GetAutonomousContainerDatabaseDataguardAssociationsAutonomousContainerDatabaseDataguardAssociationPeerAutonomousContainerDatabaseBackupConfigResult(
            ImmutableArray<Outputs.GetAutonomousContainerDatabaseDataguardAssociationsAutonomousContainerDatabaseDataguardAssociationPeerAutonomousContainerDatabaseBackupConfigBackupDestinationDetailResult> backupDestinationDetails,

            int recoveryWindowInDays)
        {
            BackupDestinationDetails = backupDestinationDetails;
            RecoveryWindowInDays = recoveryWindowInDays;
        }
    }
}
