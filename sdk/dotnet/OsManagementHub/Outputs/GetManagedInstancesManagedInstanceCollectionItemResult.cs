// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.OsManagementHub.Outputs
{

    [OutputType]
    public sealed class GetManagedInstancesManagedInstanceCollectionItemResult
    {
        /// <summary>
        /// A filter to return only managed instances with the specified version of osmh-agent running.
        /// </summary>
        public readonly string AgentVersion;
        /// <summary>
        /// The CPU architecture type of the managed instance.
        /// </summary>
        public readonly string Architecture;
        /// <summary>
        /// Settings for the Autonomous Linux service.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedInstancesManagedInstanceCollectionItemAutonomousSettingResult> AutonomousSettings;
        /// <summary>
        /// Number of bug fix type updates available for installation.
        /// </summary>
        public readonly int BugUpdatesAvailable;
        /// <summary>
        /// The OCID of the compartment that contains the resources to list. This filter returns only resources contained within the specified compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// Software source description.
        /// </summary>
        public readonly string Description;
        /// <summary>
        /// A filter to return resources that match the given display names.
        /// </summary>
        public readonly string DisplayName;
        /// <summary>
        /// Number of enhancement type updates available for installation.
        /// </summary>
        public readonly int EnhancementUpdatesAvailable;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the software source.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// Number of packages installed on the instance.
        /// </summary>
        public readonly int InstalledPackages;
        /// <summary>
        /// Number of Windows updates installed on the instance.
        /// </summary>
        public readonly int InstalledWindowsUpdates;
        /// <summary>
        /// Indicates whether to list only resources managed by the Autonomous Linux service.
        /// </summary>
        public readonly bool IsManagedByAutonomousLinux;
        /// <summary>
        /// A filter to return only managed instances that are acting as management stations.
        /// </summary>
        public readonly bool IsManagementStation;
        /// <summary>
        /// A filter to return only managed instances that require a reboot to install updates.
        /// </summary>
        public readonly bool IsRebootRequired;
        /// <summary>
        /// The ksplice effective kernel version.
        /// </summary>
        public readonly string KspliceEffectiveKernelVersion;
        /// <summary>
        /// A filter to return only managed instances in a specific lifecycle environment.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedInstancesManagedInstanceCollectionItemLifecycleEnvironmentResult> LifecycleEnvironments;
        /// <summary>
        /// A filter to return only managed instances that are associated with the specified lifecycle environment.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedInstancesManagedInstanceCollectionItemLifecycleStageResult> LifecycleStages;
        /// <summary>
        /// A filter to return only resources whose location matches the given value.
        /// </summary>
        public readonly string Location;
        /// <summary>
        /// Id and name of a resource to simplify the display for the user.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedInstancesManagedInstanceCollectionItemManagedInstanceGroupResult> ManagedInstanceGroups;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance. This filter returns resources associated with this managed instance.
        /// </summary>
        public readonly string ManagedInstanceId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the Oracle Notifications service (ONS) topic. ONS is the channel used to send notifications to the customer.
        /// </summary>
        public readonly string NotificationTopicId;
        /// <summary>
        /// A filter to return only resources that match the given operating system family.
        /// </summary>
        public readonly string OsFamily;
        /// <summary>
        /// Operating system kernel version.
        /// </summary>
        public readonly string OsKernelVersion;
        /// <summary>
        /// Operating system name.
        /// </summary>
        public readonly string OsName;
        /// <summary>
        /// Operating system version.
        /// </summary>
        public readonly string OsVersion;
        /// <summary>
        /// Number of non-classified (other) updates available for installation.
        /// </summary>
        public readonly int OtherUpdatesAvailable;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station for the instance to use as primary management station.
        /// </summary>
        public readonly string PrimaryManagementStationId;
        /// <summary>
        /// A multi filter to return only managed instances that match the given profile ids.
        /// </summary>
        public readonly string Profile;
        /// <summary>
        /// The version of the profile that was used to register this instance with the service.
        /// </summary>
        public readonly string ProfileVersion;
        /// <summary>
        /// Number of scheduled jobs associated with this instance.
        /// </summary>
        public readonly int ScheduledJobCount;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the management station for the instance to use as secondary management station.
        /// </summary>
        public readonly string SecondaryManagementStationId;
        /// <summary>
        /// Number of security type updates available for installation.
        /// </summary>
        public readonly int SecurityUpdatesAvailable;
        /// <summary>
        /// The list of software sources currently attached to the managed instance.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetManagedInstancesManagedInstanceCollectionItemSoftwareSourceResult> SoftwareSources;
        /// <summary>
        /// A filter to return only managed instances whose status matches the status provided.
        /// </summary>
        public readonly string Status;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy that the managed instance resides in.
        /// </summary>
        public readonly string TenancyId;
        /// <summary>
        /// The date and time the instance was created (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// Time that the instance last booted (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
        /// </summary>
        public readonly string TimeLastBoot;
        /// <summary>
        /// Time that the instance last checked in with the service (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
        /// </summary>
        public readonly string TimeLastCheckin;
        /// <summary>
        /// The date and time the instance was last updated (in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) format).
        /// </summary>
        public readonly string TimeUpdated;
        /// <summary>
        /// Number of updates available for installation.
        /// </summary>
        public readonly int UpdatesAvailable;
        /// <summary>
        /// Number of work requests associated with this instance.
        /// </summary>
        public readonly int WorkRequestCount;

        [OutputConstructor]
        private GetManagedInstancesManagedInstanceCollectionItemResult(
            string agentVersion,

            string architecture,

            ImmutableArray<Outputs.GetManagedInstancesManagedInstanceCollectionItemAutonomousSettingResult> autonomousSettings,

            int bugUpdatesAvailable,

            string compartmentId,

            string description,

            string displayName,

            int enhancementUpdatesAvailable,

            string id,

            int installedPackages,

            int installedWindowsUpdates,

            bool isManagedByAutonomousLinux,

            bool isManagementStation,

            bool isRebootRequired,

            string kspliceEffectiveKernelVersion,

            ImmutableArray<Outputs.GetManagedInstancesManagedInstanceCollectionItemLifecycleEnvironmentResult> lifecycleEnvironments,

            ImmutableArray<Outputs.GetManagedInstancesManagedInstanceCollectionItemLifecycleStageResult> lifecycleStages,

            string location,

            ImmutableArray<Outputs.GetManagedInstancesManagedInstanceCollectionItemManagedInstanceGroupResult> managedInstanceGroups,

            string managedInstanceId,

            string notificationTopicId,

            string osFamily,

            string osKernelVersion,

            string osName,

            string osVersion,

            int otherUpdatesAvailable,

            string primaryManagementStationId,

            string profile,

            string profileVersion,

            int scheduledJobCount,

            string secondaryManagementStationId,

            int securityUpdatesAvailable,

            ImmutableArray<Outputs.GetManagedInstancesManagedInstanceCollectionItemSoftwareSourceResult> softwareSources,

            string status,

            string tenancyId,

            string timeCreated,

            string timeLastBoot,

            string timeLastCheckin,

            string timeUpdated,

            int updatesAvailable,

            int workRequestCount)
        {
            AgentVersion = agentVersion;
            Architecture = architecture;
            AutonomousSettings = autonomousSettings;
            BugUpdatesAvailable = bugUpdatesAvailable;
            CompartmentId = compartmentId;
            Description = description;
            DisplayName = displayName;
            EnhancementUpdatesAvailable = enhancementUpdatesAvailable;
            Id = id;
            InstalledPackages = installedPackages;
            InstalledWindowsUpdates = installedWindowsUpdates;
            IsManagedByAutonomousLinux = isManagedByAutonomousLinux;
            IsManagementStation = isManagementStation;
            IsRebootRequired = isRebootRequired;
            KspliceEffectiveKernelVersion = kspliceEffectiveKernelVersion;
            LifecycleEnvironments = lifecycleEnvironments;
            LifecycleStages = lifecycleStages;
            Location = location;
            ManagedInstanceGroups = managedInstanceGroups;
            ManagedInstanceId = managedInstanceId;
            NotificationTopicId = notificationTopicId;
            OsFamily = osFamily;
            OsKernelVersion = osKernelVersion;
            OsName = osName;
            OsVersion = osVersion;
            OtherUpdatesAvailable = otherUpdatesAvailable;
            PrimaryManagementStationId = primaryManagementStationId;
            Profile = profile;
            ProfileVersion = profileVersion;
            ScheduledJobCount = scheduledJobCount;
            SecondaryManagementStationId = secondaryManagementStationId;
            SecurityUpdatesAvailable = securityUpdatesAvailable;
            SoftwareSources = softwareSources;
            Status = status;
            TenancyId = tenancyId;
            TimeCreated = timeCreated;
            TimeLastBoot = timeLastBoot;
            TimeLastCheckin = timeLastCheckin;
            TimeUpdated = timeUpdated;
            UpdatesAvailable = updatesAvailable;
            WorkRequestCount = workRequestCount;
        }
    }
}
