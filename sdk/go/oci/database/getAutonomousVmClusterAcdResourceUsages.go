// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
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
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := database.GetAutonomousVmClusterAcdResourceUsages(ctx, &database.GetAutonomousVmClusterAcdResourceUsagesArgs{
//				AutonomousVmClusterId: testAutonomousVmCluster.Id,
//				CompartmentId:         pulumi.StringRef(compartmentId),
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
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetAutonomousVmClusterAcdResourceUsagesResultOutput, error) {
			args := v.(GetAutonomousVmClusterAcdResourceUsagesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getAutonomousVmClusterAcdResourceUsages:getAutonomousVmClusterAcdResourceUsages", args, GetAutonomousVmClusterAcdResourceUsagesResultOutput{}, options).(GetAutonomousVmClusterAcdResourceUsagesResultOutput), nil
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
