// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Cloud Autonomous Vm Clusters in Oracle Cloud Infrastructure Database service.
//
// Lists Autonomous Exadata VM clusters in the Oracle cloud. For Exadata Cloud@Customer systems, see [ListAutonomousVmClusters](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/AutonomousVmCluster/ListAutonomousVmClusters).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Database.GetCloudAutonomousVmClusters(ctx, &database.GetCloudAutonomousVmClustersArgs{
//				CompartmentId:                _var.Compartment_id,
//				AvailabilityDomain:           pulumi.StringRef(_var.Cloud_autonomous_vm_cluster_availability_domain),
//				CloudExadataInfrastructureId: pulumi.StringRef(oci_database_cloud_exadata_infrastructure.Test_cloud_exadata_infrastructure.Id),
//				DisplayName:                  pulumi.StringRef(_var.Cloud_autonomous_vm_cluster_display_name),
//				State:                        pulumi.StringRef(_var.Cloud_autonomous_vm_cluster_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetCloudAutonomousVmClusters(ctx *pulumi.Context, args *GetCloudAutonomousVmClustersArgs, opts ...pulumi.InvokeOption) (*GetCloudAutonomousVmClustersResult, error) {
	var rv GetCloudAutonomousVmClustersResult
	err := ctx.Invoke("oci:Database/getCloudAutonomousVmClusters:getCloudAutonomousVmClusters", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCloudAutonomousVmClusters.
type GetCloudAutonomousVmClustersArgs struct {
	// A filter to return only resources that match the given availability domain exactly.
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// If provided, filters the results for the specified cloud Exadata infrastructure.
	CloudExadataInfrastructureId *string `pulumi:"cloudExadataInfrastructureId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName *string                              `pulumi:"displayName"`
	Filters     []GetCloudAutonomousVmClustersFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State *string `pulumi:"state"`
}

// A collection of values returned by getCloudAutonomousVmClusters.
type GetCloudAutonomousVmClustersResult struct {
	// The name of the availability domain that the cloud Autonomous VM cluster is located in.
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The list of cloud_autonomous_vm_clusters.
	CloudAutonomousVmClusters []GetCloudAutonomousVmClustersCloudAutonomousVmCluster `pulumi:"cloudAutonomousVmClusters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure.
	CloudExadataInfrastructureId *string `pulumi:"cloudExadataInfrastructureId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The user-friendly name for the cloud Autonomous VM cluster. The name does not need to be unique.
	DisplayName *string                              `pulumi:"displayName"`
	Filters     []GetCloudAutonomousVmClustersFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the cloud Autonomous VM cluster.
	State *string `pulumi:"state"`
}

func GetCloudAutonomousVmClustersOutput(ctx *pulumi.Context, args GetCloudAutonomousVmClustersOutputArgs, opts ...pulumi.InvokeOption) GetCloudAutonomousVmClustersResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetCloudAutonomousVmClustersResult, error) {
			args := v.(GetCloudAutonomousVmClustersArgs)
			r, err := GetCloudAutonomousVmClusters(ctx, &args, opts...)
			var s GetCloudAutonomousVmClustersResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetCloudAutonomousVmClustersResultOutput)
}

// A collection of arguments for invoking getCloudAutonomousVmClusters.
type GetCloudAutonomousVmClustersOutputArgs struct {
	// A filter to return only resources that match the given availability domain exactly.
	AvailabilityDomain pulumi.StringPtrInput `pulumi:"availabilityDomain"`
	// If provided, filters the results for the specified cloud Exadata infrastructure.
	CloudExadataInfrastructureId pulumi.StringPtrInput `pulumi:"cloudExadataInfrastructureId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given. The match is not case sensitive.
	DisplayName pulumi.StringPtrInput                        `pulumi:"displayName"`
	Filters     GetCloudAutonomousVmClustersFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state exactly.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetCloudAutonomousVmClustersOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCloudAutonomousVmClustersArgs)(nil)).Elem()
}

// A collection of values returned by getCloudAutonomousVmClusters.
type GetCloudAutonomousVmClustersResultOutput struct{ *pulumi.OutputState }

func (GetCloudAutonomousVmClustersResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCloudAutonomousVmClustersResult)(nil)).Elem()
}

func (o GetCloudAutonomousVmClustersResultOutput) ToGetCloudAutonomousVmClustersResultOutput() GetCloudAutonomousVmClustersResultOutput {
	return o
}

func (o GetCloudAutonomousVmClustersResultOutput) ToGetCloudAutonomousVmClustersResultOutputWithContext(ctx context.Context) GetCloudAutonomousVmClustersResultOutput {
	return o
}

// The name of the availability domain that the cloud Autonomous VM cluster is located in.
func (o GetCloudAutonomousVmClustersResultOutput) AvailabilityDomain() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCloudAutonomousVmClustersResult) *string { return v.AvailabilityDomain }).(pulumi.StringPtrOutput)
}

// The list of cloud_autonomous_vm_clusters.
func (o GetCloudAutonomousVmClustersResultOutput) CloudAutonomousVmClusters() GetCloudAutonomousVmClustersCloudAutonomousVmClusterArrayOutput {
	return o.ApplyT(func(v GetCloudAutonomousVmClustersResult) []GetCloudAutonomousVmClustersCloudAutonomousVmCluster {
		return v.CloudAutonomousVmClusters
	}).(GetCloudAutonomousVmClustersCloudAutonomousVmClusterArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the cloud Exadata infrastructure.
func (o GetCloudAutonomousVmClustersResultOutput) CloudExadataInfrastructureId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCloudAutonomousVmClustersResult) *string { return v.CloudExadataInfrastructureId }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o GetCloudAutonomousVmClustersResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetCloudAutonomousVmClustersResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The user-friendly name for the cloud Autonomous VM cluster. The name does not need to be unique.
func (o GetCloudAutonomousVmClustersResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCloudAutonomousVmClustersResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetCloudAutonomousVmClustersResultOutput) Filters() GetCloudAutonomousVmClustersFilterArrayOutput {
	return o.ApplyT(func(v GetCloudAutonomousVmClustersResult) []GetCloudAutonomousVmClustersFilter { return v.Filters }).(GetCloudAutonomousVmClustersFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetCloudAutonomousVmClustersResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetCloudAutonomousVmClustersResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of the cloud Autonomous VM cluster.
func (o GetCloudAutonomousVmClustersResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCloudAutonomousVmClustersResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetCloudAutonomousVmClustersResultOutput{})
}