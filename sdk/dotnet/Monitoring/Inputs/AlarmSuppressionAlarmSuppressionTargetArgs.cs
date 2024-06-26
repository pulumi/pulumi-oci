// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Monitoring.Inputs
{

    public sealed class AlarmSuppressionAlarmSuppressionTargetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the alarm that is the target of the alarm suppression.
        /// </summary>
        [Input("alarmId", required: true)]
        public Input<string> AlarmId { get; set; } = null!;

        /// <summary>
        /// The type of the alarm suppression target.
        /// </summary>
        [Input("targetType", required: true)]
        public Input<string> TargetType { get; set; } = null!;

        public AlarmSuppressionAlarmSuppressionTargetArgs()
        {
        }
        public static new AlarmSuppressionAlarmSuppressionTargetArgs Empty => new AlarmSuppressionAlarmSuppressionTargetArgs();
    }
}
