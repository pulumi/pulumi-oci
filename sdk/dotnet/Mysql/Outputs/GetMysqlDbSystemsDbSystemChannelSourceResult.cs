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
    public sealed class GetMysqlDbSystemsDbSystemChannelSourceResult
    {
        /// <summary>
        /// The network address of the DB System.
        /// </summary>
        public readonly string Hostname;
        /// <summary>
        /// The port for primary endpoint of the DB System to listen on.
        /// </summary>
        public readonly int Port;
        /// <summary>
        /// The specific source identifier.
        /// </summary>
        public readonly string SourceType;
        /// <summary>
        /// The CA certificate of the server used for VERIFY_IDENTITY and VERIFY_CA ssl modes.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMysqlDbSystemsDbSystemChannelSourceSslCaCertificateResult> SslCaCertificates;
        /// <summary>
        /// The SSL mode of the Channel.
        /// </summary>
        public readonly string SslMode;
        /// <summary>
        /// The name of the replication user on the source MySQL instance. The username has a maximum length of 96 characters. For more information, please see the [MySQL documentation](https://dev.mysql.com/doc/refman/8.0/en/change-master-to.html)
        /// </summary>
        public readonly string Username;

        [OutputConstructor]
        private GetMysqlDbSystemsDbSystemChannelSourceResult(
            string hostname,

            int port,

            string sourceType,

            ImmutableArray<Outputs.GetMysqlDbSystemsDbSystemChannelSourceSslCaCertificateResult> sslCaCertificates,

            string sslMode,

            string username)
        {
            Hostname = hostname;
            Port = port;
            SourceType = sourceType;
            SslCaCertificates = sslCaCertificates;
            SslMode = sslMode;
            Username = username;
        }
    }
}