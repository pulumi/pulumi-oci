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
    public sealed class ExadataInfrastructureStorageMaintenanceWindow
    {
        public readonly ImmutableArray<Outputs.ExadataInfrastructureStorageMaintenanceWindowDaysOfWeek> DaysOfWeeks;
        public readonly ImmutableArray<int> HoursOfDays;
        public readonly int? LeadTimeInWeeks;
        public readonly ImmutableArray<Outputs.ExadataInfrastructureStorageMaintenanceWindowMonth> Months;
        public readonly string Preference;
        public readonly ImmutableArray<int> WeeksOfMonths;

        [OutputConstructor]
        private ExadataInfrastructureStorageMaintenanceWindow(
            ImmutableArray<Outputs.ExadataInfrastructureStorageMaintenanceWindowDaysOfWeek> daysOfWeeks,

            ImmutableArray<int> hoursOfDays,

            int? leadTimeInWeeks,

            ImmutableArray<Outputs.ExadataInfrastructureStorageMaintenanceWindowMonth> months,

            string preference,

            ImmutableArray<int> weeksOfMonths)
        {
            DaysOfWeeks = daysOfWeeks;
            HoursOfDays = hoursOfDays;
            LeadTimeInWeeks = leadTimeInWeeks;
            Months = months;
            Preference = preference;
            WeeksOfMonths = weeksOfMonths;
        }
    }
}
