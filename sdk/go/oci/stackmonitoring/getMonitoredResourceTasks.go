// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package stackmonitoring

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides the list of Monitored Resource Tasks in Oracle Cloud Infrastructure Stack Monitoring service.
//
// Returns a list of stack monitoring resource tasks in the compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/StackMonitoring"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := StackMonitoring.GetMonitoredResourceTasks(ctx, &stackmonitoring.GetMonitoredResourceTasksArgs{
//				CompartmentId: _var.Compartment_id,
//				Status:        pulumi.StringRef(_var.Monitored_resource_task_status),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetMonitoredResourceTasks(ctx *pulumi.Context, args *GetMonitoredResourceTasksArgs, opts ...pulumi.InvokeOption) (*GetMonitoredResourceTasksResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetMonitoredResourceTasksResult
	err := ctx.Invoke("oci:StackMonitoring/getMonitoredResourceTasks:getMonitoredResourceTasks", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMonitoredResourceTasks.
type GetMonitoredResourceTasksArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for which  stack monitoring resource tasks should be listed.
	CompartmentId string                            `pulumi:"compartmentId"`
	Filters       []GetMonitoredResourceTasksFilter `pulumi:"filters"`
	// A filter to return only resources that matches with lifecycleState given.
	Status *string `pulumi:"status"`
}

// A collection of values returned by getMonitoredResourceTasks.
type GetMonitoredResourceTasksResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment identifier.
	CompartmentId string                            `pulumi:"compartmentId"`
	Filters       []GetMonitoredResourceTasksFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of monitored_resource_tasks_collection.
	MonitoredResourceTasksCollections []GetMonitoredResourceTasksMonitoredResourceTasksCollection `pulumi:"monitoredResourceTasksCollections"`
	Status                            *string                                                     `pulumi:"status"`
}

func GetMonitoredResourceTasksOutput(ctx *pulumi.Context, args GetMonitoredResourceTasksOutputArgs, opts ...pulumi.InvokeOption) GetMonitoredResourceTasksResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetMonitoredResourceTasksResult, error) {
			args := v.(GetMonitoredResourceTasksArgs)
			r, err := GetMonitoredResourceTasks(ctx, &args, opts...)
			var s GetMonitoredResourceTasksResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetMonitoredResourceTasksResultOutput)
}

// A collection of arguments for invoking getMonitoredResourceTasks.
type GetMonitoredResourceTasksOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment for which  stack monitoring resource tasks should be listed.
	CompartmentId pulumi.StringInput                        `pulumi:"compartmentId"`
	Filters       GetMonitoredResourceTasksFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that matches with lifecycleState given.
	Status pulumi.StringPtrInput `pulumi:"status"`
}

func (GetMonitoredResourceTasksOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMonitoredResourceTasksArgs)(nil)).Elem()
}

// A collection of values returned by getMonitoredResourceTasks.
type GetMonitoredResourceTasksResultOutput struct{ *pulumi.OutputState }

func (GetMonitoredResourceTasksResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMonitoredResourceTasksResult)(nil)).Elem()
}

func (o GetMonitoredResourceTasksResultOutput) ToGetMonitoredResourceTasksResultOutput() GetMonitoredResourceTasksResultOutput {
	return o
}

func (o GetMonitoredResourceTasksResultOutput) ToGetMonitoredResourceTasksResultOutputWithContext(ctx context.Context) GetMonitoredResourceTasksResultOutput {
	return o
}

func (o GetMonitoredResourceTasksResultOutput) ToOutput(ctx context.Context) pulumix.Output[GetMonitoredResourceTasksResult] {
	return pulumix.Output[GetMonitoredResourceTasksResult]{
		OutputState: o.OutputState,
	}
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment identifier.
func (o GetMonitoredResourceTasksResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetMonitoredResourceTasksResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetMonitoredResourceTasksResultOutput) Filters() GetMonitoredResourceTasksFilterArrayOutput {
	return o.ApplyT(func(v GetMonitoredResourceTasksResult) []GetMonitoredResourceTasksFilter { return v.Filters }).(GetMonitoredResourceTasksFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetMonitoredResourceTasksResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetMonitoredResourceTasksResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of monitored_resource_tasks_collection.
func (o GetMonitoredResourceTasksResultOutput) MonitoredResourceTasksCollections() GetMonitoredResourceTasksMonitoredResourceTasksCollectionArrayOutput {
	return o.ApplyT(func(v GetMonitoredResourceTasksResult) []GetMonitoredResourceTasksMonitoredResourceTasksCollection {
		return v.MonitoredResourceTasksCollections
	}).(GetMonitoredResourceTasksMonitoredResourceTasksCollectionArrayOutput)
}

func (o GetMonitoredResourceTasksResultOutput) Status() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMonitoredResourceTasksResult) *string { return v.Status }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetMonitoredResourceTasksResultOutput{})
}