// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Oci.CloudMigrations
{
    public static class GetMigrationPlanAvailableShapes
    {
        /// <summary>
        /// This data source provides the list of Migration Plan Available Shapes in Oracle Cloud Infrastructure Cloud Migrations service.
        /// 
        /// List of shapes by parameters.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testMigrationPlanAvailableShapes = Oci.CloudMigrations.GetMigrationPlanAvailableShapes.Invoke(new()
        ///     {
        ///         MigrationPlanId = oci_cloud_migrations_migration_plan.Test_migration_plan.Id,
        ///         AvailabilityDomain = @var.Migration_plan_available_shape_availability_domain,
        ///         CompartmentId = @var.Compartment_id,
        ///         DvhHostId = oci_cloud_migrations_dvh_host.Test_dvh_host.Id,
        ///         ReservedCapacityId = oci_cloud_migrations_reserved_capacity.Test_reserved_capacity.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Task<GetMigrationPlanAvailableShapesResult> InvokeAsync(GetMigrationPlanAvailableShapesArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.InvokeAsync<GetMigrationPlanAvailableShapesResult>("oci:CloudMigrations/getMigrationPlanAvailableShapes:getMigrationPlanAvailableShapes", args ?? new GetMigrationPlanAvailableShapesArgs(), options.WithDefaults());

        /// <summary>
        /// This data source provides the list of Migration Plan Available Shapes in Oracle Cloud Infrastructure Cloud Migrations service.
        /// 
        /// List of shapes by parameters.
        /// 
        /// {{% examples %}}
        /// ## Example Usage
        /// {{% example %}}
        /// 
        /// ```csharp
        /// using System.Collections.Generic;
        /// using Pulumi;
        /// using Oci = Pulumi.Oci;
        /// 
        /// return await Deployment.RunAsync(() =&gt; 
        /// {
        ///     var testMigrationPlanAvailableShapes = Oci.CloudMigrations.GetMigrationPlanAvailableShapes.Invoke(new()
        ///     {
        ///         MigrationPlanId = oci_cloud_migrations_migration_plan.Test_migration_plan.Id,
        ///         AvailabilityDomain = @var.Migration_plan_available_shape_availability_domain,
        ///         CompartmentId = @var.Compartment_id,
        ///         DvhHostId = oci_cloud_migrations_dvh_host.Test_dvh_host.Id,
        ///         ReservedCapacityId = oci_cloud_migrations_reserved_capacity.Test_reserved_capacity.Id,
        ///     });
        /// 
        /// });
        /// ```
        /// {{% /example %}}
        /// {{% /examples %}}
        /// </summary>
        public static Output<GetMigrationPlanAvailableShapesResult> Invoke(GetMigrationPlanAvailableShapesInvokeArgs args, InvokeOptions? options = null)
            => global::Pulumi.Deployment.Instance.Invoke<GetMigrationPlanAvailableShapesResult>("oci:CloudMigrations/getMigrationPlanAvailableShapes:getMigrationPlanAvailableShapes", args ?? new GetMigrationPlanAvailableShapesInvokeArgs(), options.WithDefaults());
    }


    public sealed class GetMigrationPlanAvailableShapesArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The availability domain in which to list resources.
        /// </summary>
        [Input("availabilityDomain")]
        public string? AvailabilityDomain { get; set; }

        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public string? CompartmentId { get; set; }

        /// <summary>
        /// The ID of the Dvh in which to list resources.
        /// </summary>
        [Input("dvhHostId")]
        public string? DvhHostId { get; set; }

        [Input("filters")]
        private List<Inputs.GetMigrationPlanAvailableShapesFilterArgs>? _filters;
        public List<Inputs.GetMigrationPlanAvailableShapesFilterArgs> Filters
        {
            get => _filters ?? (_filters = new List<Inputs.GetMigrationPlanAvailableShapesFilterArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique migration plan identifier
        /// </summary>
        [Input("migrationPlanId", required: true)]
        public string MigrationPlanId { get; set; } = null!;

        /// <summary>
        /// The reserved capacity ID for which to list resources.
        /// </summary>
        [Input("reservedCapacityId")]
        public string? ReservedCapacityId { get; set; }

        public GetMigrationPlanAvailableShapesArgs()
        {
        }
        public static new GetMigrationPlanAvailableShapesArgs Empty => new GetMigrationPlanAvailableShapesArgs();
    }

    public sealed class GetMigrationPlanAvailableShapesInvokeArgs : global::Pulumi.InvokeArgs
    {
        /// <summary>
        /// The availability domain in which to list resources.
        /// </summary>
        [Input("availabilityDomain")]
        public Input<string>? AvailabilityDomain { get; set; }

        /// <summary>
        /// The ID of the compartment in which to list resources.
        /// </summary>
        [Input("compartmentId")]
        public Input<string>? CompartmentId { get; set; }

        /// <summary>
        /// The ID of the Dvh in which to list resources.
        /// </summary>
        [Input("dvhHostId")]
        public Input<string>? DvhHostId { get; set; }

        [Input("filters")]
        private InputList<Inputs.GetMigrationPlanAvailableShapesFilterInputArgs>? _filters;
        public InputList<Inputs.GetMigrationPlanAvailableShapesFilterInputArgs> Filters
        {
            get => _filters ?? (_filters = new InputList<Inputs.GetMigrationPlanAvailableShapesFilterInputArgs>());
            set => _filters = value;
        }

        /// <summary>
        /// Unique migration plan identifier
        /// </summary>
        [Input("migrationPlanId", required: true)]
        public Input<string> MigrationPlanId { get; set; } = null!;

        /// <summary>
        /// The reserved capacity ID for which to list resources.
        /// </summary>
        [Input("reservedCapacityId")]
        public Input<string>? ReservedCapacityId { get; set; }

        public GetMigrationPlanAvailableShapesInvokeArgs()
        {
        }
        public static new GetMigrationPlanAvailableShapesInvokeArgs Empty => new GetMigrationPlanAvailableShapesInvokeArgs();
    }


    [OutputType]
    public sealed class GetMigrationPlanAvailableShapesResult
    {
        /// <summary>
        /// Availability domain of the shape.
        /// </summary>
        public readonly string? AvailabilityDomain;
        /// <summary>
        /// The list of available_shapes_collection.
        /// </summary>
        public readonly ImmutableArray<Outputs.GetMigrationPlanAvailableShapesAvailableShapesCollectionResult> AvailableShapesCollections;
        public readonly string? CompartmentId;
        public readonly string? DvhHostId;
        public readonly ImmutableArray<Outputs.GetMigrationPlanAvailableShapesFilterResult> Filters;
        /// <summary>
        /// The provider-assigned unique ID for this managed resource.
        /// </summary>
        public readonly string Id;
        public readonly string MigrationPlanId;
        public readonly string? ReservedCapacityId;

        [OutputConstructor]
        private GetMigrationPlanAvailableShapesResult(
            string? availabilityDomain,

            ImmutableArray<Outputs.GetMigrationPlanAvailableShapesAvailableShapesCollectionResult> availableShapesCollections,

            string? compartmentId,

            string? dvhHostId,

            ImmutableArray<Outputs.GetMigrationPlanAvailableShapesFilterResult> filters,

            string id,

            string migrationPlanId,

            string? reservedCapacityId)
        {
            AvailabilityDomain = availabilityDomain;
            AvailableShapesCollections = availableShapesCollections;
            CompartmentId = compartmentId;
            DvhHostId = dvhHostId;
            Filters = filters;
            Id = id;
            MigrationPlanId = migrationPlanId;
            ReservedCapacityId = reservedCapacityId;
        }
    }
}