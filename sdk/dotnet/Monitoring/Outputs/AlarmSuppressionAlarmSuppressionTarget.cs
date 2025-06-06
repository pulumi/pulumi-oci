// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Monitoring.Outputs
{

    [OutputType]
    public sealed class AlarmSuppressionAlarmSuppressionTarget
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm that is the target of the alarm suppression.
        /// </summary>
        public readonly string? AlarmId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment or tenancy that is the  target of the alarm suppression. Example: `ocid1.compartment.oc1..exampleuniqueID`
        /// </summary>
        public readonly string? CompartmentId;
        /// <summary>
        /// When true, the alarm suppression targets all alarms under all compartments and subcompartments of  the tenancy specified. The parameter can only be set to true when compartmentId is the tenancy OCID  (the tenancy is the root compartment). When false, the alarm suppression targets only the alarms under the specified compartment.
        /// </summary>
        public readonly bool? CompartmentIdInSubtree;
        /// <summary>
        /// The type of the alarm suppression target.
        /// </summary>
        public readonly string TargetType;

        [OutputConstructor]
        private AlarmSuppressionAlarmSuppressionTarget(
            string? alarmId,

            string? compartmentId,

            bool? compartmentIdInSubtree,

            string targetType)
        {
            AlarmId = alarmId;
            CompartmentId = compartmentId;
            CompartmentIdInSubtree = compartmentIdInSubtree;
            TargetType = targetType;
        }
    }
}
