// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Cloud Autonomous Vm Cluster Acd Resource Usages in Oracle Cloud Infrastructure Database service.
//
// Gets the list of resource usage details for all the Cloud Autonomous Container Database
// in the specified Cloud Autonomous Exadata VM cluster.
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
//			_, err := database.GetCloudAutonomousVmClusterAcdResourceUsages(ctx, &database.GetCloudAutonomousVmClusterAcdResourceUsagesArgs{
//				CloudAutonomousVmClusterId: testCloudAutonomousVmCluster.Id,
//				CompartmentId:              pulumi.StringRef(compartmentId),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetCloudAutonomousVmClusterAcdResourceUsages(ctx *pulumi.Context, args *GetCloudAutonomousVmClusterAcdResourceUsagesArgs, opts ...pulumi.InvokeOption) (*GetCloudAutonomousVmClusterAcdResourceUsagesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetCloudAutonomousVmClusterAcdResourceUsagesResult
	err := ctx.Invoke("oci:Database/getCloudAutonomousVmClusterAcdResourceUsages:getCloudAutonomousVmClusterAcdResourceUsages", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCloudAutonomousVmClusterAcdResourceUsages.
type GetCloudAutonomousVmClusterAcdResourceUsagesArgs struct {
	// The Cloud VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CloudAutonomousVmClusterId string `pulumi:"cloudAutonomousVmClusterId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId *string                                              `pulumi:"compartmentId"`
	Filters       []GetCloudAutonomousVmClusterAcdResourceUsagesFilter `pulumi:"filters"`
}

// A collection of values returned by getCloudAutonomousVmClusterAcdResourceUsages.
type GetCloudAutonomousVmClusterAcdResourceUsagesResult struct {
	// The list of autonomous_container_database_resource_usages.
	AutonomousContainerDatabaseResourceUsages []GetCloudAutonomousVmClusterAcdResourceUsagesAutonomousContainerDatabaseResourceUsage `pulumi:"autonomousContainerDatabaseResourceUsages"`
	CloudAutonomousVmClusterId                string                                                                                 `pulumi:"cloudAutonomousVmClusterId"`
	CompartmentId                             *string                                                                                `pulumi:"compartmentId"`
	Filters                                   []GetCloudAutonomousVmClusterAcdResourceUsagesFilter                                   `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetCloudAutonomousVmClusterAcdResourceUsagesOutput(ctx *pulumi.Context, args GetCloudAutonomousVmClusterAcdResourceUsagesOutputArgs, opts ...pulumi.InvokeOption) GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput, error) {
			args := v.(GetCloudAutonomousVmClusterAcdResourceUsagesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Database/getCloudAutonomousVmClusterAcdResourceUsages:getCloudAutonomousVmClusterAcdResourceUsages", args, GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput{}, options).(GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput), nil
		}).(GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput)
}

// A collection of arguments for invoking getCloudAutonomousVmClusterAcdResourceUsages.
type GetCloudAutonomousVmClusterAcdResourceUsagesOutputArgs struct {
	// The Cloud VM cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CloudAutonomousVmClusterId pulumi.StringInput `pulumi:"cloudAutonomousVmClusterId"`
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringPtrInput                                        `pulumi:"compartmentId"`
	Filters       GetCloudAutonomousVmClusterAcdResourceUsagesFilterArrayInput `pulumi:"filters"`
}

func (GetCloudAutonomousVmClusterAcdResourceUsagesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCloudAutonomousVmClusterAcdResourceUsagesArgs)(nil)).Elem()
}

// A collection of values returned by getCloudAutonomousVmClusterAcdResourceUsages.
type GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput struct{ *pulumi.OutputState }

func (GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCloudAutonomousVmClusterAcdResourceUsagesResult)(nil)).Elem()
}

func (o GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput) ToGetCloudAutonomousVmClusterAcdResourceUsagesResultOutput() GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput {
	return o
}

func (o GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput) ToGetCloudAutonomousVmClusterAcdResourceUsagesResultOutputWithContext(ctx context.Context) GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput {
	return o
}

// The list of autonomous_container_database_resource_usages.
func (o GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput) AutonomousContainerDatabaseResourceUsages() GetCloudAutonomousVmClusterAcdResourceUsagesAutonomousContainerDatabaseResourceUsageArrayOutput {
	return o.ApplyT(func(v GetCloudAutonomousVmClusterAcdResourceUsagesResult) []GetCloudAutonomousVmClusterAcdResourceUsagesAutonomousContainerDatabaseResourceUsage {
		return v.AutonomousContainerDatabaseResourceUsages
	}).(GetCloudAutonomousVmClusterAcdResourceUsagesAutonomousContainerDatabaseResourceUsageArrayOutput)
}

func (o GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput) CloudAutonomousVmClusterId() pulumi.StringOutput {
	return o.ApplyT(func(v GetCloudAutonomousVmClusterAcdResourceUsagesResult) string { return v.CloudAutonomousVmClusterId }).(pulumi.StringOutput)
}

func (o GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCloudAutonomousVmClusterAcdResourceUsagesResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

func (o GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput) Filters() GetCloudAutonomousVmClusterAcdResourceUsagesFilterArrayOutput {
	return o.ApplyT(func(v GetCloudAutonomousVmClusterAcdResourceUsagesResult) []GetCloudAutonomousVmClusterAcdResourceUsagesFilter {
		return v.Filters
	}).(GetCloudAutonomousVmClusterAcdResourceUsagesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetCloudAutonomousVmClusterAcdResourceUsagesResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetCloudAutonomousVmClusterAcdResourceUsagesResultOutput{})
}
