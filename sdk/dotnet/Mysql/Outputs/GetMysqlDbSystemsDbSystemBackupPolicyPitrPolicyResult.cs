// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Outputs
{

    [OutputType]
    public sealed class GetMysqlDbSystemsDbSystemBackupPolicyPitrPolicyResult
    {
        /// <summary>
        /// Whether the Channel has been enabled by the user.
        /// </summary>
        public readonly bool IsEnabled;

        [OutputConstructor]
        private GetMysqlDbSystemsDbSystemBackupPolicyPitrPolicyResult(bool isEnabled)
        {
            IsEnabled = isEnabled;
        }
    }
}
