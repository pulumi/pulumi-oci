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
    public sealed class GetShapeShapePlatformConfigOptionResult
    {
        public readonly ImmutableArray<Outputs.GetShapeShapePlatformConfigOptionMeasuredBootOptionResult> MeasuredBootOptions;
        public readonly ImmutableArray<Outputs.GetShapeShapePlatformConfigOptionNumaNodesPerSocketPlatformOptionResult> NumaNodesPerSocketPlatformOptions;
        public readonly ImmutableArray<Outputs.GetShapeShapePlatformConfigOptionSecureBootOptionResult> SecureBootOptions;
        public readonly ImmutableArray<Outputs.GetShapeShapePlatformConfigOptionTrustedPlatformModuleOptionResult> TrustedPlatformModuleOptions;
        public readonly string Type;

        [OutputConstructor]
        private GetShapeShapePlatformConfigOptionResult(
            ImmutableArray<Outputs.GetShapeShapePlatformConfigOptionMeasuredBootOptionResult> measuredBootOptions,

            ImmutableArray<Outputs.GetShapeShapePlatformConfigOptionNumaNodesPerSocketPlatformOptionResult> numaNodesPerSocketPlatformOptions,

            ImmutableArray<Outputs.GetShapeShapePlatformConfigOptionSecureBootOptionResult> secureBootOptions,

            ImmutableArray<Outputs.GetShapeShapePlatformConfigOptionTrustedPlatformModuleOptionResult> trustedPlatformModuleOptions,

            string type)
        {
            MeasuredBootOptions = measuredBootOptions;
            NumaNodesPerSocketPlatformOptions = numaNodesPerSocketPlatformOptions;
            SecureBootOptions = secureBootOptions;
            TrustedPlatformModuleOptions = trustedPlatformModuleOptions;
            Type = type;
        }
    }
}
