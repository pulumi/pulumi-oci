// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides the list of Autonomous Vm Cluster Acd Resource Usages in Oracle Cloud Infrastructure Database service.
//
// Gets the list of resource usage details for all the Autonomous Container Database in the specified Autonomous Exadata VM cluster.
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
//			_, err := Database.GetAutonomousVmClusterAcdResourceUsages(ctx, &database.GetAutonomousVmClusterAcdResourceUsagesArgs{
//				AutonomousVmClusterId: oci_database_autonomous_vm_cluster.Test_autonomous_vm_cluster.Id,
//				CompartmentId:         pulumi.StringRef(_var.Compartment_id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetAutonomousVmClusterAcdResourceUsages(ctx *pulumi.Context, args *GetAutonomousVmClusterAcdResourceUsagesArgs, opts ...pulumi.InvokeOption) (*GetAutonomousVmClusterAcdResourceUsagesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetAutonomousVmClusterAcdResourceUsagesResult
	err := ctx.Invoke("oci:Database/getAutonomousVmClusterAcdResourceUsages:getAutonomousVmClusterAcdResourceUsages", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAutonomousVmClusterAcdResourceUsages.
type GetAutonomousVmClusterAcdResourceUsagesArgs struct {
	// The autonomous VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousVmClusterId string `pulumi:"autonomousVmClusterId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId *string                                         `pulumi:"compartmentId"`
	Filters       []GetAutonomousVmClusterAcdResourceUsagesFilter `pulumi:"filters"`
}

// A collection of values returned by getAutonomousVmClusterAcdResourceUsages.
type GetAutonomousVmClusterAcdResourceUsagesResult struct {
	// The list of autonomous_container_database_resource_usages.
	AutonomousContainerDatabaseResourceUsages []GetAutonomousVmClusterAcdResourceUsagesAutonomousContainerDatabaseResourceUsage `pulumi:"autonomousContainerDatabaseResourceUsages"`
	AutonomousVmClusterId                     string                                                                            `pulumi:"autonomousVmClusterId"`
	CompartmentId                             *string                                                                           `pulumi:"compartmentId"`
	Filters                                   []GetAutonomousVmClusterAcdResourceUsagesFilter                                   `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetAutonomousVmClusterAcdResourceUsagesOutput(ctx *pulumi.Context, args GetAutonomousVmClusterAcdResourceUsagesOutputArgs, opts ...pulumi.InvokeOption) GetAutonomousVmClusterAcdResourceUsagesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetAutonomousVmClusterAcdResourceUsagesResult, error) {
			args := v.(GetAutonomousVmClusterAcdResourceUsagesArgs)
			r, err := GetAutonomousVmClusterAcdResourceUsages(ctx, &args, opts...)
			var s GetAutonomousVmClusterAcdResourceUsagesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetAutonomousVmClusterAcdResourceUsagesResultOutput)
}

// A collection of arguments for invoking getAutonomousVmClusterAcdResourceUsages.
type GetAutonomousVmClusterAcdResourceUsagesOutputArgs struct {
	// The autonomous VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	AutonomousVmClusterId pulumi.StringInput `pulumi:"autonomousVmClusterId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringPtrInput                                   `pulumi:"compartmentId"`
	Filters       GetAutonomousVmClusterAcdResourceUsagesFilterArrayInput `pulumi:"filters"`
}

func (GetAutonomousVmClusterAcdResourceUsagesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAutonomousVmClusterAcdResourceUsagesArgs)(nil)).Elem()
}

// A collection of values returned by getAutonomousVmClusterAcdResourceUsages.
type GetAutonomousVmClusterAcdResourceUsagesResultOutput struct{ *pulumi.OutputState }

func (GetAutonomousVmClusterAcdResourceUsagesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAutonomousVmClusterAcdResourceUsagesResult)(nil)).Elem()
}

func (o GetAutonomousVmClusterAcdResourceUsagesResultOutput) ToGetAutonomousVmClusterAcdResourceUsagesResultOutput() GetAutonomousVmClusterAcdResourceUsagesResultOutput {
	return o
}

func (o GetAutonomousVmClusterAcdResourceUsagesResultOutput) ToGetAutonomousVmClusterAcdResourceUsagesResultOutputWithContext(ctx context.Context) GetAutonomousVmClusterAcdResourceUsagesResultOutput {
	return o
}

func (o GetAutonomousVmClusterAcdResourceUsagesResultOutput) ToOutput(ctx context.Context) pulumix.Output[GetAutonomousVmClusterAcdResourceUsagesResult] {
	return pulumix.Output[GetAutonomousVmClusterAcdResourceUsagesResult]{
		OutputState: o.OutputState,
	}
}

// The list of autonomous_container_database_resource_usages.
func (o GetAutonomousVmClusterAcdResourceUsagesResultOutput) AutonomousContainerDatabaseResourceUsages() GetAutonomousVmClusterAcdResourceUsagesAutonomousContainerDatabaseResourceUsageArrayOutput {
	return o.ApplyT(func(v GetAutonomousVmClusterAcdResourceUsagesResult) []GetAutonomousVmClusterAcdResourceUsagesAutonomousContainerDatabaseResourceUsage {
		return v.AutonomousContainerDatabaseResourceUsages
	}).(GetAutonomousVmClusterAcdResourceUsagesAutonomousContainerDatabaseResourceUsageArrayOutput)
}

func (o GetAutonomousVmClusterAcdResourceUsagesResultOutput) AutonomousVmClusterId() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousVmClusterAcdResourceUsagesResult) string { return v.AutonomousVmClusterId }).(pulumi.StringOutput)
}

func (o GetAutonomousVmClusterAcdResourceUsagesResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAutonomousVmClusterAcdResourceUsagesResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

func (o GetAutonomousVmClusterAcdResourceUsagesResultOutput) Filters() GetAutonomousVmClusterAcdResourceUsagesFilterArrayOutput {
	return o.ApplyT(func(v GetAutonomousVmClusterAcdResourceUsagesResult) []GetAutonomousVmClusterAcdResourceUsagesFilter {
		return v.Filters
	}).(GetAutonomousVmClusterAcdResourceUsagesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetAutonomousVmClusterAcdResourceUsagesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetAutonomousVmClusterAcdResourceUsagesResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetAutonomousVmClusterAcdResourceUsagesResultOutput{})
}