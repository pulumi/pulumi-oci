// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Mysql.Inputs
{

    public sealed class MysqlDbSystemChannelSourceAnonymousTransactionsHandlingGetArgs : global::Pulumi.ResourceArgs
    {
        /// <summary>
        /// Specifies one of the coordinates (file) at which the replica should begin reading the source's log. As this value specifies the point where replication starts from, it is only used once, when it starts. It is never used again, unless a new UpdateChannel operation modifies it.
        /// </summary>
        [Input("lastConfiguredLogFilename")]
        public Input<string>? LastConfiguredLogFilename { get; set; }

        /// <summary>
        /// Specifies one of the coordinates (offset) at which the replica should begin reading the source's log. As this value specifies the point where replication starts from, it is only used once, when it starts. It is never used again, unless a new UpdateChannel operation modifies it.
        /// </summary>
        [Input("lastConfiguredLogOffset")]
        public Input<string>? LastConfiguredLogOffset { get; set; }

        /// <summary>
        /// Specifies how the replication channel handles anonymous transactions.
        /// </summary>
        [Input("policy")]
        public Input<string>? Policy { get; set; }

        /// <summary>
        /// The UUID that is used as a prefix when generating transaction identifiers for anonymous transactions coming from the source. You can change the UUID later.
        /// </summary>
        [Input("uuid")]
        public Input<string>? Uuid { get; set; }

        public MysqlDbSystemChannelSourceAnonymousTransactionsHandlingGetArgs()
        {
        }
        public static new MysqlDbSystemChannelSourceAnonymousTransactionsHandlingGetArgs Empty => new MysqlDbSystemChannelSourceAnonymousTransactionsHandlingGetArgs();
    }
}