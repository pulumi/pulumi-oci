// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database
{
    public static class GetDbSystemsUpgradeHistoryEntry
    {
        /// <summary>
        /// This data source provides details about a specific Db Systems Upgrade History Entry resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets the details of the specified operating system upgrade operation for the specified DB system.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testDbSystemsUpgradeHistoryEntry = Oci.Database.GetDbSystemsUpgradeHistoryEntry.Invoke(new()
        ///     {
        ///         DbSystemId = oci_database_db_system.Test_db_system.Id,
        ///         UpgradeHistoryEntryId = oci_database_upgrade_history_entry.Test_upgrade_history_entry.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetDbSystemsUpgradeHistoryEntryResult> InvokeAsync(GetDbSystemsUpgradeHistoryEntryArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetDbSystemsUpgradeHistoryEntryResult>("oci:Database/getDbSystemsUpgradeHistoryEntry:getDbSystemsUpgradeHistoryEntry", args ?? new GetDbSystemsUpgradeHistoryEntryArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides details about a specific Db Systems Upgrade History Entry resource in Oracle Cloud Infrastructure Database service.
        /// 
        /// Gets the details of the specified operating system upgrade operation for the specified DB system.
        /// 
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testDbSystemsUpgradeHistoryEntry = Oci.Database.GetDbSystemsUpgradeHistoryEntry.Invoke(new()
        ///     {
        ///         DbSystemId = oci_database_db_system.Test_db_system.Id,
        ///         UpgradeHistoryEntryId = oci_database_upgrade_history_entry.Test_upgrade_history_entry.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetDbSystemsUpgradeHistoryEntryResult> Invoke(GetDbSystemsUpgradeHistoryEntryInvokeArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.Invoke<GetDbSystemsUpgradeHistoryEntryResult>("oci:Database/getDbSystemsUpgradeHistoryEntry:getDbSystemsUpgradeHistoryEntry", args ?? new GetDbSystemsUpgradeHistoryEntryInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetDbSystemsUpgradeHistoryEntryArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("dbSystemId", required: true)]
        public string DbSystemId { get; set; } = null!;

        /// <summary>
        /// The database/db system upgrade History [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("upgradeHistoryEntryId", required: true)]
        public string UpgradeHistoryEntryId { get; set; } = null!;

        public GetDbSystemsUpgradeHistoryEntryArgs()
        {
        }
        public static new GetDbSystemsUpgradeHistoryEntryArgs Empty => new GetDbSystemsUpgradeHistoryEntryArgs();
    }

    public sealed class GetDbSystemsUpgradeHistoryEntryInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The DB system [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("dbSystemId", required: true)]
        public Input<string> DbSystemId { get; set; } = null!;

        /// <summary>
        /// The database/db system upgrade History [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
        /// </summary>
        [Input("upgradeHistoryEntryId", required: true)]
        public Input<string> UpgradeHistoryEntryId { get; set; } = null!;

        public GetDbSystemsUpgradeHistoryEntryInvokeArgs()
        {
        }
        public static new GetDbSystemsUpgradeHistoryEntryInvokeArgs Empty => new GetDbSystemsUpgradeHistoryEntryInvokeArgs();
    }


    [OutputType]
    public sealed class GetDbSystemsUpgradeHistoryEntryResult
    {
        /// <summary>
        /// The operating system upgrade action.
        /// </summary>
        public readonly string Action;
        public readonly string DbSystemId;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// A descriptive text associated with the lifecycleState. Typically contains additional displayable text.
        /// </summary>
        public readonly string LifecycleDetails;
        /// <summary>
        /// A valid Oracle Grid Infrastructure (GI) software version.
        /// </summary>
        public readonly string NewGiVersion;
        /// <summary>
        /// A valid Oracle Grid Infrastructure (GI) software version.
        /// </summary>
        public readonly string OldGiVersion;
        /// <summary>
        /// The retention period, in days, for the snapshot that allows you to perform a rollback of the upgrade operation. After this number of days passes, you cannot roll back the upgrade.
        /// </summary>
        public readonly int SnapshotRetentionPeriodInDays;
        /// <summary>
        /// The current state of the action.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// The date and time when the upgrade action completed
        /// </summary>
        public readonly string TimeEnded;
        /// <summary>
        /// The date and time when the upgrade action started.
        /// </summary>
        public readonly string TimeStarted;
        public readonly string UpgradeHistoryEntryId;

        [OutputConstructor]
        private GetDbSystemsUpgradeHistoryEntryResult(
            string action,

            string dbSystemId,

            string id,

            string lifecycleDetails,

            string newGiVersion,

            string oldGiVersion,

            int snapshotRetentionPeriodInDays,

            string state,

            string timeEnded,

            string timeStarted,

            string upgradeHistoryEntryId)
        {
            Action = action;
            DbSystemId = dbSystemId;
            Id = id;
            LifecycleDetails = lifecycleDetails;
            NewGiVersion = newGiVersion;
            OldGiVersion = oldGiVersion;
            SnapshotRetentionPeriodInDays = snapshotRetentionPeriodInDays;
            State = state;
            TimeEnded = timeEnded;
            TimeStarted = timeStarted;
            UpgradeHistoryEntryId = upgradeHistoryEntryId;
        }
    }
}