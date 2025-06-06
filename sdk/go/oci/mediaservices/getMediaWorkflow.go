// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mediaservices

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Media Workflow resource in Oracle Cloud Infrastructure Media Services service.
//
// Gets a MediaWorkflow by identifier.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/mediaservices"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := mediaservices.GetMediaWorkflow(ctx, &mediaservices.GetMediaWorkflowArgs{
//				MediaWorkflowId: testMediaWorkflowOciMediaServicesMediaWorkflow.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupMediaWorkflow(ctx *pulumi.Context, args *LookupMediaWorkflowArgs, opts ...pulumi.InvokeOption) (*LookupMediaWorkflowResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupMediaWorkflowResult
	err := ctx.Invoke("oci:MediaServices/getMediaWorkflow:getMediaWorkflow", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMediaWorkflow.
type LookupMediaWorkflowArgs struct {
	// Unique MediaWorkflow identifier.
	MediaWorkflowId string `pulumi:"mediaWorkflowId"`
}

// A collection of values returned by getMediaWorkflow.
type LookupMediaWorkflowResult struct {
	// The compartment ID of the lock.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Name of the Media Workflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// Unique identifier that is immutable on creation.
	Id             string `pulumi:"id"`
	IsLockOverride bool   `pulumi:"isLockOverride"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecyleDetails string `pulumi:"lifecyleDetails"`
	// Locks associated with this resource.
	Locks []GetMediaWorkflowLock `pulumi:"locks"`
	// Configurations to be applied to all the runs of this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob. If the same parameter appears in multiple configurations, the values that appear in the configuration at the highest index will be used.
	MediaWorkflowConfigurationIds []string `pulumi:"mediaWorkflowConfigurationIds"`
	MediaWorkflowId               string   `pulumi:"mediaWorkflowId"`
	// Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
	Parameters string `pulumi:"parameters"`
	// The current state of the MediaWorkflow.
	State string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array is unique within the array.  The order of the items is preserved from the order of the tasks array in CreateMediaWorkflowDetails or UpdateMediaWorkflowDetails.
	Tasks []GetMediaWorkflowTask `pulumi:"tasks"`
	// The time when the MediaWorkflow was created. An RFC3339 formatted datetime string.
	TimeCreated string `pulumi:"timeCreated"`
	// The time when the MediaWorkflow was updated. An RFC3339 formatted datetime string.
	TimeUpdated string `pulumi:"timeUpdated"`
	// The version of the MediaWorkflow.
	Version string `pulumi:"version"`
}

func LookupMediaWorkflowOutput(ctx *pulumi.Context, args LookupMediaWorkflowOutputArgs, opts ...pulumi.InvokeOption) LookupMediaWorkflowResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupMediaWorkflowResultOutput, error) {
			args := v.(LookupMediaWorkflowArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:MediaServices/getMediaWorkflow:getMediaWorkflow", args, LookupMediaWorkflowResultOutput{}, options).(LookupMediaWorkflowResultOutput), nil
		}).(LookupMediaWorkflowResultOutput)
}

// A collection of arguments for invoking getMediaWorkflow.
type LookupMediaWorkflowOutputArgs struct {
	// Unique MediaWorkflow identifier.
	MediaWorkflowId pulumi.StringInput `pulumi:"mediaWorkflowId"`
}

func (LookupMediaWorkflowOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupMediaWorkflowArgs)(nil)).Elem()
}

// A collection of values returned by getMediaWorkflow.
type LookupMediaWorkflowResultOutput struct{ *pulumi.OutputState }

func (LookupMediaWorkflowResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupMediaWorkflowResult)(nil)).Elem()
}

func (o LookupMediaWorkflowResultOutput) ToLookupMediaWorkflowResultOutput() LookupMediaWorkflowResultOutput {
	return o
}

func (o LookupMediaWorkflowResultOutput) ToLookupMediaWorkflowResultOutputWithContext(ctx context.Context) LookupMediaWorkflowResultOutput {
	return o
}

// The compartment ID of the lock.
func (o LookupMediaWorkflowResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupMediaWorkflowResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Name of the Media Workflow. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o LookupMediaWorkflowResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupMediaWorkflowResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// Unique identifier that is immutable on creation.
func (o LookupMediaWorkflowResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o LookupMediaWorkflowResultOutput) IsLockOverride() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) bool { return v.IsLockOverride }).(pulumi.BoolOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
func (o LookupMediaWorkflowResultOutput) LifecyleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) string { return v.LifecyleDetails }).(pulumi.StringOutput)
}

// Locks associated with this resource.
func (o LookupMediaWorkflowResultOutput) Locks() GetMediaWorkflowLockArrayOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) []GetMediaWorkflowLock { return v.Locks }).(GetMediaWorkflowLockArrayOutput)
}

// Configurations to be applied to all the runs of this workflow. Parameters in these configurations are overridden by parameters in the MediaWorkflowConfigurations of the MediaWorkflowJob and the parameters of the MediaWorkflowJob. If the same parameter appears in multiple configurations, the values that appear in the configuration at the highest index will be used.
func (o LookupMediaWorkflowResultOutput) MediaWorkflowConfigurationIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) []string { return v.MediaWorkflowConfigurationIds }).(pulumi.StringArrayOutput)
}

func (o LookupMediaWorkflowResultOutput) MediaWorkflowId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) string { return v.MediaWorkflowId }).(pulumi.StringOutput)
}

// Data specifiying how this task is to be run. The data is a JSON object that must conform to the JSON Schema specified by the parameters of the MediaWorkflowTaskDeclaration this task references. The parameters may contain values or references to other parameters.
func (o LookupMediaWorkflowResultOutput) Parameters() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) string { return v.Parameters }).(pulumi.StringOutput)
}

// The current state of the MediaWorkflow.
func (o LookupMediaWorkflowResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) string { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupMediaWorkflowResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The processing to be done in this workflow. Each key of the MediaWorkflowTasks in this array is unique within the array.  The order of the items is preserved from the order of the tasks array in CreateMediaWorkflowDetails or UpdateMediaWorkflowDetails.
func (o LookupMediaWorkflowResultOutput) Tasks() GetMediaWorkflowTaskArrayOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) []GetMediaWorkflowTask { return v.Tasks }).(GetMediaWorkflowTaskArrayOutput)
}

// The time when the MediaWorkflow was created. An RFC3339 formatted datetime string.
func (o LookupMediaWorkflowResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when the MediaWorkflow was updated. An RFC3339 formatted datetime string.
func (o LookupMediaWorkflowResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The version of the MediaWorkflow.
func (o LookupMediaWorkflowResultOutput) Version() pulumi.StringOutput {
	return o.ApplyT(func(v LookupMediaWorkflowResult) string { return v.Version }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupMediaWorkflowResultOutput{})
}
