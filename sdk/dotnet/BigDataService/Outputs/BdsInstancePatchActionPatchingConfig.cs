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
    public sealed class BdsInstancePatchActionPatchingConfig
    {
        /// <summary>
        /// How many nodes to be patched in each iteration.
        /// </summary>
        public readonly int? BatchSize;
        /// <summary>
        /// Type of strategy used for detailed patching configuration
        /// </summary>
        public readonly string PatchingConfigStrategy;
        /// <summary>
        /// The wait time between batches in seconds.
        /// </summary>
        public readonly int? WaitTimeBetweenBatchInSeconds;
        /// <summary>
        /// The wait time between AD/FD in seconds.
        /// </summary>
        public readonly int? WaitTimeBetweenDomainInSeconds;

        [OutputConstructor]
        private BdsInstancePatchActionPatchingConfig(
            int? batchSize,

            string patchingConfigStrategy,

            int? waitTimeBetweenBatchInSeconds,

            int? waitTimeBetweenDomainInSeconds)
        {
            BatchSize = batchSize;
            PatchingConfigStrategy = patchingConfigStrategy;
            WaitTimeBetweenBatchInSeconds = waitTimeBetweenBatchInSeconds;
            WaitTimeBetweenDomainInSeconds = waitTimeBetweenDomainInSeconds;
        }
    }
}
