// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Analytics.Outputs
{

    [OutputType]
    public sealed class AnalyticsInstancePrivateAccessChannelPrivateSourceScanHost
    {
        /// <summary>
        /// (Updatable) Description of private source scan host zone.
        /// </summary>
        public readonly string? Description;
        /// <summary>
        /// (Updatable) Private Source Scan hostname. Ex: db01-scan.corp.example.com, prd-db01-scan.mycompany.com.
        /// </summary>
        public readonly string ScanHostname;
        /// <summary>
        /// (Updatable) Private Source Scan host port. This is the source port where SCAN protocol will get connected (e.g. 1521).
        /// </summary>
        public readonly int ScanPort;

        [OutputConstructor]
        private AnalyticsInstancePrivateAccessChannelPrivateSourceScanHost(
            string? description,

            string scanHostname,

            int scanPort)
        {
            Description = description;
            ScanHostname = scanHostname;
            ScanPort = scanPort;
        }
    }
}