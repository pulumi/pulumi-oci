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
    public sealed class FleetAdvancedFeatureConfigurationCryptoEventAnalysisSummarizedEventsLog
    {
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log group.
        /// </summary>
        public readonly string LogGroupId;
        /// <summary>
        /// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the log.
        /// </summary>
        public readonly string LogId;

        [OutputConstructor]
        private FleetAdvancedFeatureConfigurationCryptoEventAnalysisSummarizedEventsLog(
            string logGroupId,

            string logId)
        {
            LogGroupId = logGroupId;
            LogId = logId;
        }
    }
}
