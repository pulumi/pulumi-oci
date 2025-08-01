// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Oci.Outputs
{

    [OutputType]
    public sealed class GetWlmsWlsDomainAgreementRecordsAgreementRecordCollectionItemResult
    {
        /// <summary>
        /// The agreement signature.
        /// </summary>
        public readonly string AgreementSignature;
        /// <summary>
        /// The ID of the accepted agreement.
        /// </summary>
        public readonly string AgreementUuid;
        /// <summary>
        /// The accepted time for the agreement record.
        /// </summary>
        public readonly string TimeAccepted;

        [OutputConstructor]
        private GetWlmsWlsDomainAgreementRecordsAgreementRecordCollectionItemResult(
            string agreementSignature,

            string agreementUuid,

            string timeAccepted)
        {
            AgreementSignature = agreementSignature;
            AgreementUuid = agreementUuid;
            TimeAccepted = timeAccepted;
        }
    }
}
