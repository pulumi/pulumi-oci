// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.BigDataService.Outputs
{

    [OutputType]
    public sealed class BdsInstanceCloudSqlDetailKerberosDetail
    {
        /// <summary>
        /// Location of the keytab file
        /// </summary>
        public readonly string? KeytabFile;
        /// <summary>
        /// Name of the Kerberos principal
        /// </summary>
        public readonly string? PrincipalName;

        [OutputConstructor]
        private BdsInstanceCloudSqlDetailKerberosDetail(
            string? keytabFile,

            string? principalName)
        {
            KeytabFile = keytabFile;
            PrincipalName = principalName;
        }
    }
}
