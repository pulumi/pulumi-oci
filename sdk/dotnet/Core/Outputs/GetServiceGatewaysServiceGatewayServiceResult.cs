// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetServiceGatewaysServiceGatewayServiceResult
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the service.
        /// </summary>
        public readonly string ServiceId;
        /// <summary>
        /// The name of the service.
        /// </summary>
        public readonly string ServiceName;

        [OutputConstructor]
        private GetServiceGatewaysServiceGatewayServiceResult(
            string serviceId,

            string serviceName)
        {
            ServiceId = serviceId;
            ServiceName = serviceName;
        }
    }
}