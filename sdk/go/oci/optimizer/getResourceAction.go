// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package optimizer

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Resource Action resource in Oracle Cloud Infrastructure Optimizer service.
//
// Gets the resource action that corresponds to the specified OCID.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Optimizer"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Optimizer.GetResourceAction(ctx, &optimizer.GetResourceActionArgs{
//				ResourceActionId: oci_optimizer_resource_action.Test_resource_action.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupResourceAction(ctx *pulumi.Context, args *LookupResourceActionArgs, opts ...pulumi.InvokeOption) (*LookupResourceActionResult, error) {
	var rv LookupResourceActionResult
	err := ctx.Invoke("oci:Optimizer/getResourceAction:getResourceAction", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getResourceAction.
type LookupResourceActionArgs struct {
	// The unique OCID associated with the resource action.
	ResourceActionId string `pulumi:"resourceActionId"`
}

// A collection of values returned by getResourceAction.
type LookupResourceActionResult struct {
	// Details about the recommended action.
	Actions []GetResourceActionAction `pulumi:"actions"`
	// The unique OCID associated with the category.
	CategoryId string `pulumi:"categoryId"`
	// The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The name associated with the compartment.
	CompartmentName string `pulumi:"compartmentName"`
	// The estimated cost savings, in dollars, for the resource action.
	EstimatedCostSaving float64 `pulumi:"estimatedCostSaving"`
	// Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
	ExtendedMetadata map[string]interface{} `pulumi:"extendedMetadata"`
	// The unique OCID associated with the resource action.
	Id string `pulumi:"id"`
	// Custom metadata key/value pairs for the resource action.
	Metadata map[string]interface{} `pulumi:"metadata"`
	// The name assigned to the resource.
	Name string `pulumi:"name"`
	// The unique OCID associated with the recommendation.
	RecommendationId string `pulumi:"recommendationId"`
	ResourceActionId string `pulumi:"resourceActionId"`
	// The unique OCID associated with the resource.
	ResourceId string `pulumi:"resourceId"`
	// The kind of resource.
	ResourceType string `pulumi:"resourceType"`
	// The resource action's current state.
	State string `pulumi:"state"`
	// The current status of the resource action.
	Status string `pulumi:"status"`
	// The date and time the resource action details were created, in the format defined by RFC3339.
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time that the resource action entered its current status. The format is defined by RFC3339.
	TimeStatusBegin string `pulumi:"timeStatusBegin"`
	// The date and time the current status will change. The format is defined by RFC3339.
	TimeStatusEnd string `pulumi:"timeStatusEnd"`
	// The date and time the resource action details were last updated, in the format defined by RFC3339.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupResourceActionOutput(ctx *pulumi.Context, args LookupResourceActionOutputArgs, opts ...pulumi.InvokeOption) LookupResourceActionResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupResourceActionResult, error) {
			args := v.(LookupResourceActionArgs)
			r, err := LookupResourceAction(ctx, &args, opts...)
			var s LookupResourceActionResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupResourceActionResultOutput)
}

// A collection of arguments for invoking getResourceAction.
type LookupResourceActionOutputArgs struct {
	// The unique OCID associated with the resource action.
	ResourceActionId pulumi.StringInput `pulumi:"resourceActionId"`
}

func (LookupResourceActionOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupResourceActionArgs)(nil)).Elem()
}

// A collection of values returned by getResourceAction.
type LookupResourceActionResultOutput struct{ *pulumi.OutputState }

func (LookupResourceActionResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupResourceActionResult)(nil)).Elem()
}

func (o LookupResourceActionResultOutput) ToLookupResourceActionResultOutput() LookupResourceActionResultOutput {
	return o
}

func (o LookupResourceActionResultOutput) ToLookupResourceActionResultOutputWithContext(ctx context.Context) LookupResourceActionResultOutput {
	return o
}

// Details about the recommended action.
func (o LookupResourceActionResultOutput) Actions() GetResourceActionActionArrayOutput {
	return o.ApplyT(func(v LookupResourceActionResult) []GetResourceActionAction { return v.Actions }).(GetResourceActionActionArrayOutput)
}

// The unique OCID associated with the category.
func (o LookupResourceActionResultOutput) CategoryId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResourceActionResult) string { return v.CategoryId }).(pulumi.StringOutput)
}

// The OCID of the compartment.
func (o LookupResourceActionResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResourceActionResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The name associated with the compartment.
func (o LookupResourceActionResultOutput) CompartmentName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResourceActionResult) string { return v.CompartmentName }).(pulumi.StringOutput)
}

// The estimated cost savings, in dollars, for the resource action.
func (o LookupResourceActionResultOutput) EstimatedCostSaving() pulumi.Float64Output {
	return o.ApplyT(func(v LookupResourceActionResult) float64 { return v.EstimatedCostSaving }).(pulumi.Float64Output)
}

// Additional metadata key/value pairs that you provide. They serve the same purpose and functionality as fields in the `metadata` object.
func (o LookupResourceActionResultOutput) ExtendedMetadata() pulumi.MapOutput {
	return o.ApplyT(func(v LookupResourceActionResult) map[string]interface{} { return v.ExtendedMetadata }).(pulumi.MapOutput)
}

// The unique OCID associated with the resource action.
func (o LookupResourceActionResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResourceActionResult) string { return v.Id }).(pulumi.StringOutput)
}

// Custom metadata key/value pairs for the resource action.
func (o LookupResourceActionResultOutput) Metadata() pulumi.MapOutput {
	return o.ApplyT(func(v LookupResourceActionResult) map[string]interface{} { return v.Metadata }).(pulumi.MapOutput)
}

// The name assigned to the resource.
func (o LookupResourceActionResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResourceActionResult) string { return v.Name }).(pulumi.StringOutput)
}

// The unique OCID associated with the recommendation.
func (o LookupResourceActionResultOutput) RecommendationId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResourceActionResult) string { return v.RecommendationId }).(pulumi.StringOutput)
}

func (o LookupResourceActionResultOutput) ResourceActionId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResourceActionResult) string { return v.ResourceActionId }).(pulumi.StringOutput)
}

// The unique OCID associated with the resource.
func (o LookupResourceActionResultOutput) ResourceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResourceActionResult) string { return v.ResourceId }).(pulumi.StringOutput)
}

// The kind of resource.
func (o LookupResourceActionResultOutput) ResourceType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResourceActionResult) string { return v.ResourceType }).(pulumi.StringOutput)
}

// The resource action's current state.
func (o LookupResourceActionResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResourceActionResult) string { return v.State }).(pulumi.StringOutput)
}

// The current status of the resource action.
func (o LookupResourceActionResultOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResourceActionResult) string { return v.Status }).(pulumi.StringOutput)
}

// The date and time the resource action details were created, in the format defined by RFC3339.
func (o LookupResourceActionResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResourceActionResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time that the resource action entered its current status. The format is defined by RFC3339.
func (o LookupResourceActionResultOutput) TimeStatusBegin() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResourceActionResult) string { return v.TimeStatusBegin }).(pulumi.StringOutput)
}

// The date and time the current status will change. The format is defined by RFC3339.
func (o LookupResourceActionResultOutput) TimeStatusEnd() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResourceActionResult) string { return v.TimeStatusEnd }).(pulumi.StringOutput)
}

// The date and time the resource action details were last updated, in the format defined by RFC3339.
func (o LookupResourceActionResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupResourceActionResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupResourceActionResultOutput{})
}