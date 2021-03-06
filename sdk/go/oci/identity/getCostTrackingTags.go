// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Cost Tracking Tags in Oracle Cloud Infrastructure Identity service.
//
// Lists all the tags enabled for cost-tracking in the specified tenancy. For information about
// cost-tracking tags, see [Using Cost-tracking Tags](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/taggingoverview.htm#costs).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/Identity"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := Identity.GetCostTrackingTags(ctx, &identity.GetCostTrackingTagsArgs{
// 			CompartmentId: _var.Compartment_id,
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetCostTrackingTags(ctx *pulumi.Context, args *GetCostTrackingTagsArgs, opts ...pulumi.InvokeOption) (*GetCostTrackingTagsResult, error) {
	var rv GetCostTrackingTagsResult
	err := ctx.Invoke("oci:Identity/getCostTrackingTags:getCostTrackingTags", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCostTrackingTags.
type GetCostTrackingTagsArgs struct {
	// The OCID of the compartment (remember that the tenancy is simply the root compartment).
	CompartmentId string                      `pulumi:"compartmentId"`
	Filters       []GetCostTrackingTagsFilter `pulumi:"filters"`
}

// A collection of values returned by getCostTrackingTags.
type GetCostTrackingTagsResult struct {
	// The OCID of the compartment that contains the tag definition.
	CompartmentId string                      `pulumi:"compartmentId"`
	Filters       []GetCostTrackingTagsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of tags.
	Tags []GetCostTrackingTagsTag `pulumi:"tags"`
}

func GetCostTrackingTagsOutput(ctx *pulumi.Context, args GetCostTrackingTagsOutputArgs, opts ...pulumi.InvokeOption) GetCostTrackingTagsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetCostTrackingTagsResult, error) {
			args := v.(GetCostTrackingTagsArgs)
			r, err := GetCostTrackingTags(ctx, &args, opts...)
			var s GetCostTrackingTagsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetCostTrackingTagsResultOutput)
}

// A collection of arguments for invoking getCostTrackingTags.
type GetCostTrackingTagsOutputArgs struct {
	// The OCID of the compartment (remember that the tenancy is simply the root compartment).
	CompartmentId pulumi.StringInput                  `pulumi:"compartmentId"`
	Filters       GetCostTrackingTagsFilterArrayInput `pulumi:"filters"`
}

func (GetCostTrackingTagsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCostTrackingTagsArgs)(nil)).Elem()
}

// A collection of values returned by getCostTrackingTags.
type GetCostTrackingTagsResultOutput struct{ *pulumi.OutputState }

func (GetCostTrackingTagsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCostTrackingTagsResult)(nil)).Elem()
}

func (o GetCostTrackingTagsResultOutput) ToGetCostTrackingTagsResultOutput() GetCostTrackingTagsResultOutput {
	return o
}

func (o GetCostTrackingTagsResultOutput) ToGetCostTrackingTagsResultOutputWithContext(ctx context.Context) GetCostTrackingTagsResultOutput {
	return o
}

// The OCID of the compartment that contains the tag definition.
func (o GetCostTrackingTagsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetCostTrackingTagsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetCostTrackingTagsResultOutput) Filters() GetCostTrackingTagsFilterArrayOutput {
	return o.ApplyT(func(v GetCostTrackingTagsResult) []GetCostTrackingTagsFilter { return v.Filters }).(GetCostTrackingTagsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetCostTrackingTagsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetCostTrackingTagsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of tags.
func (o GetCostTrackingTagsResultOutput) Tags() GetCostTrackingTagsTagArrayOutput {
	return o.ApplyT(func(v GetCostTrackingTagsResult) []GetCostTrackingTagsTag { return v.Tags }).(GetCostTrackingTagsTagArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetCostTrackingTagsResultOutput{})
}
