// *** WARNING: this file was generated by pulumi-language-dotnet. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.Core.Outputs
{

    [OutputType]
    public sealed class GetShapeShapeRecommendedAlternativeResult
    {
        public readonly string ShapeName;

        [OutputConstructor]
        private GetShapeShapeRecommendedAlternativeResult(string shapeName)
        {
            ShapeName = shapeName;
        }
    }
}
