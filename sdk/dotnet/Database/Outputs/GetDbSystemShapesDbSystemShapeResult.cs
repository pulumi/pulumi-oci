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
    public sealed class GetDbSystemShapesDbSystemShapeResult
    {
        /// <summary>
        /// The maximum number of CPU cores that can be enabled on the DB system for this shape.
        /// </summary>
        public readonly int AvailableCoreCount;
        /// <summary>
        /// The maximum number of CPU cores per database node that can be enabled for this shape. Only applicable to the flex Exadata shape and ExaCC Elastic shapes.
        /// </summary>
        public readonly int AvailableCoreCountPerNode;
        /// <summary>
        /// The maximum DATA storage that can be enabled for this shape.
        /// </summary>
        public readonly int AvailableDataStorageInTbs;
        /// <summary>
        /// The maximum data storage available per storage server for this shape. Only applicable to ExaCC Elastic shapes.
        /// </summary>
        public readonly double AvailableDataStoragePerServerInTbs;
        /// <summary>
        /// The maximum Db Node storage available per database node for this shape. Only applicable to ExaCC Elastic shapes.
        /// </summary>
        public readonly int AvailableDbNodePerNodeInGbs;
        /// <summary>
        /// The maximum Db Node storage that can be enabled for this shape.
        /// </summary>
        public readonly int AvailableDbNodeStorageInGbs;
        /// <summary>
        /// The maximum memory that can be enabled for this shape.
        /// </summary>
        public readonly int AvailableMemoryInGbs;
        /// <summary>
        /// The maximum memory available per database node for this shape. Only applicable to ExaCC Elastic shapes.
        /// </summary>
        public readonly int AvailableMemoryPerNodeInGbs;
        /// <summary>
        /// The discrete number by which the CPU core count for this shape can be increased or decreased.
        /// </summary>
        public readonly int CoreCountIncrement;
        /// <summary>
        /// The maximum number of Exadata storage servers available for the Exadata infrastructure.
        /// </summary>
        public readonly int MaxStorageCount;
        /// <summary>
        /// The maximum number of database nodes available for this shape.
        /// </summary>
        public readonly int MaximumNodeCount;
        /// <summary>
        /// The minimum number of CPU cores that can be enabled per node for this shape.
        /// </summary>
        public readonly int MinCoreCountPerNode;
        /// <summary>
        /// The minimum data storage that need be allocated for this shape.
        /// </summary>
        public readonly int MinDataStorageInTbs;
        /// <summary>
        /// The minimum Db Node storage that need be allocated per node for this shape.
        /// </summary>
        public readonly int MinDbNodeStoragePerNodeInGbs;
        /// <summary>
        /// The minimum memory that need be allocated per node for this shape.
        /// </summary>
        public readonly int MinMemoryPerNodeInGbs;
        /// <summary>
        /// The minimum number of Exadata storage servers available for the Exadata infrastructure.
        /// </summary>
        public readonly int MinStorageCount;
        /// <summary>
        /// The minimum number of CPU cores that can be enabled on the DB system for this shape.
        /// </summary>
        public readonly int MinimumCoreCount;
        /// <summary>
        /// The minimum number of database nodes available for this shape.
        /// </summary>
        public readonly int MinimumNodeCount;
        /// <summary>
        /// The name of the shape used for the DB system.
        /// </summary>
        public readonly string Name;
        /// <summary>
        /// Deprecated. Use `name` instead of `shape`.
        /// </summary>
        public readonly string Shape;
        /// <summary>
        /// The family of the shape used for the DB system.
        /// </summary>
        public readonly string ShapeFamily;
        /// <summary>
        /// The shape type for the virtual machine DB system. Shape type is determined by CPU hardware. Valid values are `AMD` and `INTEL`.
        /// </summary>
        public readonly string ShapeType;

        [OutputConstructor]
        private GetDbSystemShapesDbSystemShapeResult(
            int availableCoreCount,

            int availableCoreCountPerNode,

            int availableDataStorageInTbs,

            double availableDataStoragePerServerInTbs,

            int availableDbNodePerNodeInGbs,

            int availableDbNodeStorageInGbs,

            int availableMemoryInGbs,

            int availableMemoryPerNodeInGbs,

            int coreCountIncrement,

            int maxStorageCount,

            int maximumNodeCount,

            int minCoreCountPerNode,

            int minDataStorageInTbs,

            int minDbNodeStoragePerNodeInGbs,

            int minMemoryPerNodeInGbs,

            int minStorageCount,

            int minimumCoreCount,

            int minimumNodeCount,

            string name,

            string shape,

            string shapeFamily,

            string shapeType)
        {
            AvailableCoreCount = availableCoreCount;
            AvailableCoreCountPerNode = availableCoreCountPerNode;
            AvailableDataStorageInTbs = availableDataStorageInTbs;
            AvailableDataStoragePerServerInTbs = availableDataStoragePerServerInTbs;
            AvailableDbNodePerNodeInGbs = availableDbNodePerNodeInGbs;
            AvailableDbNodeStorageInGbs = availableDbNodeStorageInGbs;
            AvailableMemoryInGbs = availableMemoryInGbs;
            AvailableMemoryPerNodeInGbs = availableMemoryPerNodeInGbs;
            CoreCountIncrement = coreCountIncrement;
            MaxStorageCount = maxStorageCount;
            MaximumNodeCount = maximumNodeCount;
            MinCoreCountPerNode = minCoreCountPerNode;
            MinDataStorageInTbs = minDataStorageInTbs;
            MinDbNodeStoragePerNodeInGbs = minDbNodeStoragePerNodeInGbs;
            MinMemoryPerNodeInGbs = minMemoryPerNodeInGbs;
            MinStorageCount = minStorageCount;
            MinimumCoreCount = minimumCoreCount;
            MinimumNodeCount = minimumNodeCount;
            Name = name;
            Shape = shape;
            ShapeFamily = shapeFamily;
            ShapeType = shapeType;
        }
    }
}