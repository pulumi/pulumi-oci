// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Oda.Outputs
{

    [OutputType]
    public sealed class GetOdaPrivateEndpointAttachmentsOdaPrivateEndpointAttachmentCollectionItemResult
    {
        /// <summary>
        /// List the ODA Private Endpoint Attachments that belong to this compartment.
        /// </summary>
        public readonly string CompartmentId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the ODA Private Endpoint Attachment.
        /// </summary>
        public readonly string Id;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the attached ODA Instance.
        /// </summary>
        public readonly string OdaInstanceId;
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of ODA Private Endpoint.
        /// </summary>
        public readonly string OdaPrivateEndpointId;
        /// <summary>
        /// List only the ODA Private Endpoint Attachments that are in this lifecycle state.
        /// </summary>
        public readonly string State;
        /// <summary>
        /// When the resource was created. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        /// </summary>
        public readonly string TimeCreated;
        /// <summary>
        /// When the resource was last updated. A date-time string as described in [RFC 3339](https://tools.ietf.org/rfc/rfc3339), section 14.29.
        /// </summary>
        public readonly string TimeUpdated;

        [OutputConstructor]
        private GetOdaPrivateEndpointAttachmentsOdaPrivateEndpointAttachmentCollectionItemResult(
            string compartmentId,

            string id,

            string odaInstanceId,

            string odaPrivateEndpointId,

            string state,

            string timeCreated,

            string timeUpdated)
        {
            CompartmentId = compartmentId;
            Id = id;
            OdaInstanceId = odaInstanceId;
            OdaPrivateEndpointId = odaPrivateEndpointId;
            State = state;
            TimeCreated = timeCreated;
            TimeUpdated = timeUpdated;
        }
    }
}