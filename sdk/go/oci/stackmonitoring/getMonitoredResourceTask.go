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

// This data source provides details about a specific Monitored Resource Task resource in Oracle Cloud Infrastructure Stack Monitoring service.
//
// Gets stack monitoring resource task details by identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
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
//			_, err := StackMonitoring.GetMonitoredResourceTask(ctx, &stackmonitoring.GetMonitoredResourceTaskArgs{
//				MonitoredResourceTaskId: oci_stack_monitoring_monitored_resource_task.Test_monitored_resource_task.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupMonitoredResourceTask(ctx *pulumi.Context, args *LookupMonitoredResourceTaskArgs, opts ...pulumi.InvokeOption) (*LookupMonitoredResourceTaskResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupMonitoredResourceTaskResult
	err := ctx.Invoke("oci:StackMonitoring/getMonitoredResourceTask:getMonitoredResourceTask", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMonitoredResourceTask.
type LookupMonitoredResourceTaskArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of stack monitoring resource task.
	MonitoredResourceTaskId string `pulumi:"monitoredResourceTaskId"`
}

// A collection of values returned by getMonitoredResourceTask.
type LookupMonitoredResourceTaskResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment identifier.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// Task identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	Id                      string `pulumi:"id"`
	MonitoredResourceTaskId string `pulumi:"monitoredResourceTaskId"`
	// Name of the task.
	Name string `pulumi:"name"`
	// The current state of the stack monitoring resource task.
	State string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// The request details for the performing the task.
	TaskDetails []GetMonitoredResourceTaskTaskDetail `pulumi:"taskDetails"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
	TenantId string `pulumi:"tenantId"`
	// The date and time when the stack monitoring resource task was created, expressed in  [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time when the stack monitoring resource task was last updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
	TimeUpdated string `pulumi:"timeUpdated"`
	// Identifiers [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for work requests submitted for this task.
	WorkRequestIds []string `pulumi:"workRequestIds"`
}

func LookupMonitoredResourceTaskOutput(ctx *pulumi.Context, args LookupMonitoredResourceTaskOutputArgs, opts ...pulumi.InvokeOption) LookupMonitoredResourceTaskResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupMonitoredResourceTaskResult, error) {
			args := v.(LookupMonitoredResourceTaskArgs)
			r, err := LookupMonitoredResourceTask(ctx, &args, opts...)
			var s LookupMonitoredResourceTaskResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupMonitoredResourceTaskResultOutput)
}

// A collection of arguments for invoking getMonitoredResourceTask.
type LookupMonitoredResourceTaskOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of stack monitoring resource task.
	MonitoredResourceTaskId pulumi.StringInput `pulumi:"monitoredResourceTaskId"`
}

func (LookupMonitoredResourceTaskOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupMonitoredResourceTaskArgs)(nil)).Elem()
}

// A collection of values returned by getMonitoredResourceTask.
type LookupMonitoredResourceTaskResultOutput struct{ *pulumi.OutputState }

func (LookupMonitoredResourceTaskResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupMonitoredResourceTaskResult)(nil)).Elem()
}

func (o LookupMonitoredResourceTaskResultOutput) ToLookupMonitoredResourceTaskResultOutput() LookupMonitoredResourceTaskResultOutput {
	return o
}

func (o LookupMonitoredResourceTaskResultOutput) ToLookupMonitoredResourceTaskResultOutputWithContext(ctx context.Context) LookupMonitoredResourceTaskResultOutput {
	return o
}

func (o LookupMonitoredResourceTaskResultOutput) ToOutput(ctx context.Context) pulumix.Output[LookupMonitoredResourceTaskResult] {
	return pulumix.Output[LookupMonitoredResourceTaskResult]{
		OutputState: o.OutputState,
	}
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment identifier.
func (o LookupMonitoredResourceTaskResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceTaskResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupMonitoredResourceTaskResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupMonitoredResourceTaskResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupMonitoredResourceTaskResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupMonitoredResourceTaskResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// Task identifier [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
func (o LookupMonitoredResourceTaskResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceTaskResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o LookupMonitoredResourceTaskResultOutput) MonitoredResourceTaskId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceTaskResult) string { return v.MonitoredResourceTaskId }).(pulumi.StringOutput)
}

// Name of the task.
func (o LookupMonitoredResourceTaskResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceTaskResult) string { return v.Name }).(pulumi.StringOutput)
}

// The current state of the stack monitoring resource task.
func (o LookupMonitoredResourceTaskResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceTaskResult) string { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupMonitoredResourceTaskResultOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupMonitoredResourceTaskResult) map[string]interface{} { return v.SystemTags }).(pulumi.MapOutput)
}

// The request details for the performing the task.
func (o LookupMonitoredResourceTaskResultOutput) TaskDetails() GetMonitoredResourceTaskTaskDetailArrayOutput {
	return o.ApplyT(func(v LookupMonitoredResourceTaskResult) []GetMonitoredResourceTaskTaskDetail { return v.TaskDetails }).(GetMonitoredResourceTaskTaskDetailArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
func (o LookupMonitoredResourceTaskResultOutput) TenantId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceTaskResult) string { return v.TenantId }).(pulumi.StringOutput)
}

// The date and time when the stack monitoring resource task was created, expressed in  [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
func (o LookupMonitoredResourceTaskResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceTaskResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time when the stack monitoring resource task was last updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.
func (o LookupMonitoredResourceTaskResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMonitoredResourceTaskResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// Identifiers [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for work requests submitted for this task.
func (o LookupMonitoredResourceTaskResultOutput) WorkRequestIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupMonitoredResourceTaskResult) []string { return v.WorkRequestIds }).(pulumi.StringArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupMonitoredResourceTaskResultOutput{})
}