// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Database.Outputs
{

    [OutputType]
    public sealed class PluggableDatabaseManagementsManagementCredentialDetails
    {
        /// <summary>
        /// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Oracle Cloud Infrastructure [secret](https://docs.cloud.oracle.com/iaas/Content/KeyManagement/Concepts/keyoverview.htm#concepts).
        /// </summary>
        public readonly string PasswordSecretId;
        /// <summary>
        /// The name of the Oracle Database user that will be used to connect to the database.
        /// </summary>
        public readonly string UserName;

        [OutputConstructor]
        private PluggableDatabaseManagementsManagementCredentialDetails(
            string passwordSecretId,

            string userName)
        {
            PasswordSecretId = passwordSecretId;
            UserName = userName;
        }
    }
}