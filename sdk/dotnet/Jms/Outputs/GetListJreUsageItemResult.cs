// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Jms.Outputs
{

    [OutputType]
    public sealed class GetListJreUsageItemResult
    {
        /// <summary>
        /// The approximate count of the applications running on this Java Runtime.
        /// </summary>
        public readonly int ApproximateApplicationCount;
        /// <summary>
        /// The approximate count of installations that are installations of this Java Runtime.
        /// </summary>
        public readonly int ApproximateInstallationCount;
        /// <summary>
        /// The approximate count of the managed instances that report this Java Runtime.
        /// </summary>
        public readonly int ApproximateManagedInstanceCount;
        /// <summary>
        /// The approximate count of work requests working on this Java Runtime.
        /// </summary>
        public readonly int ApproximatePendingWorkRequestCount;
        /// <summary>
        /// The number of days since this release has been under the security baseline.
        /// </summary>
        public readonly int DaysUnderSecurityBaseline;
        /// <summary>
        /// The distribution of a Java Runtime is the name of the lineage of product to which it belongs, for example _Java(TM) SE Runtime Environment_.
        /// </summary>
        public readonly string Distribution;
        /// <summary>
        /// The End of Support Life (EOSL) date of the Java Runtime (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        public readonly string EndOfSupportLifeDate;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related fleet.
        /// </summary>
        public readonly string FleetId;
        /// <summary>
        /// The internal identifier of the Java Runtime.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the related managed instance. This property value is present only for /listJreUsage.
        /// </summary>
        public readonly string ManagedInstanceId;
        /// <summary>
        /// The operating systems that have this Java Runtime installed.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetListJreUsageItemOperatingSystemResult> OperatingSystems;
        /// <summary>
        /// The release date of the Java Runtime (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        public readonly string ReleaseDate;
        /// <summary>
        /// The security status of the Java Runtime.
        /// </summary>
        public readonly string SecurityStatus;
        /// <summary>
        /// The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        public readonly string TimeEnd;
        /// <summary>
        /// The date and time the resource was _first_ reported to JMS. This is potentially _before_ the specified time period provided by the filters. For example, a resource can be first reported to JMS before the start of a specified time period, if it is also reported during the time period.
        /// </summary>
        public readonly string TimeFirstSeen;
        /// <summary>
        /// The date and time the resource was _last_ reported to JMS. This is potentially _after_ the specified time period provided by the filters. For example, a resource can be last reported to JMS before the start of a specified time period, if it is also reported during the time period.
        /// </summary>
        public readonly string TimeLastSeen;
        /// <summary>
        /// The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
        /// </summary>
        public readonly string TimeStart;
        /// <summary>
        /// The vendor of the Java Runtime.
        /// </summary>
        public readonly string Vendor;
        /// <summary>
        /// The version of the Java Runtime.
        /// </summary>
        public readonly string Version;

        [OutputConstructor]
        private GetListJreUsageItemResult(
            int approximateApplicationCount,

            int approximateInstallationCount,

            int approximateManagedInstanceCount,

            int approximatePendingWorkRequestCount,

            int daysUnderSecurityBaseline,

            string distribution,

            string endOfSupportLifeDate,

            string fleetId,

            string id,

            string managedInstanceId,

            ImmutableArray<Outputs.GetListJreUsageItemOperatingSystemResult> operatingSystems,

            string releaseDate,

            string securityStatus,

            string timeEnd,

            string timeFirstSeen,

            string timeLastSeen,

            string timeStart,

            string vendor,

            string version)
        {
            ApproximateApplicationCount = approximateApplicationCount;
            ApproximateInstallationCount = approximateInstallationCount;
            ApproximateManagedInstanceCount = approximateManagedInstanceCount;
            ApproximatePendingWorkRequestCount = approximatePendingWorkRequestCount;
            DaysUnderSecurityBaseline = daysUnderSecurityBaseline;
            Distribution = distribution;
            EndOfSupportLifeDate = endOfSupportLifeDate;
            FleetId = fleetId;
            Id = id;
            ManagedInstanceId = managedInstanceId;
            OperatingSystems = operatingSystems;
            ReleaseDate = releaseDate;
            SecurityStatus = securityStatus;
            TimeEnd = timeEnd;
            TimeFirstSeen = timeFirstSeen;
            TimeLastSeen = timeLastSeen;
            TimeStart = timeStart;
            Vendor = vendor;
            Version = version;
        }
    }
}
