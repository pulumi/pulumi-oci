// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dns

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Views in Oracle Cloud Infrastructure DNS service.
//
// Gets a list of all views within a compartment. The collection can
// be filtered by display name, id, or lifecycle state. It can be sorted
// on creation time or displayName both in ASC or DESC order. Note that
// when no lifecycleState query parameter is provided, the collection
// does not include views in the DELETED lifecycleState to be consistent
// with other operations of the API. Requires a `PRIVATE` scope query parameter.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Dns"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Dns.GetViews(ctx, &dns.GetViewsArgs{
//				CompartmentId: _var.Compartment_id,
//				Scope:         pulumi.StringRef("PRIVATE"),
//				DisplayName:   pulumi.StringRef(_var.View_display_name),
//				Id:            pulumi.StringRef(_var.View_id),
//				State:         pulumi.StringRef(_var.View_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetViews(ctx *pulumi.Context, args *GetViewsArgs, opts ...pulumi.InvokeOption) (*GetViewsResult, error) {
	var rv GetViewsResult
	err := ctx.Invoke("oci:Dns/getViews:getViews", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getViews.
type GetViewsArgs struct {
	// The OCID of the compartment the resource belongs to.
	CompartmentId string `pulumi:"compartmentId"`
	// The displayName of a resource.
	DisplayName *string          `pulumi:"displayName"`
	Filters     []GetViewsFilter `pulumi:"filters"`
	// The OCID of a resource.
	Id *string `pulumi:"id"`
	// Value must be `PRIVATE` when listing private views.
	Scope *string `pulumi:"scope"`
	// The state of a resource.
	State *string `pulumi:"state"`
}

// A collection of values returned by getViews.
type GetViewsResult struct {
	// The OCID of the owning compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// The display name of the view.
	DisplayName *string          `pulumi:"displayName"`
	Filters     []GetViewsFilter `pulumi:"filters"`
	// The OCID of the view.
	Id    *string `pulumi:"id"`
	Scope *string `pulumi:"scope"`
	// The current state of the resource.
	State *string `pulumi:"state"`
	// The list of views.
	Views []GetViewsView `pulumi:"views"`
}

func GetViewsOutput(ctx *pulumi.Context, args GetViewsOutputArgs, opts ...pulumi.InvokeOption) GetViewsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetViewsResult, error) {
			args := v.(GetViewsArgs)
			r, err := GetViews(ctx, &args, opts...)
			var s GetViewsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetViewsResultOutput)
}

// A collection of arguments for invoking getViews.
type GetViewsOutputArgs struct {
	// The OCID of the compartment the resource belongs to.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The displayName of a resource.
	DisplayName pulumi.StringPtrInput    `pulumi:"displayName"`
	Filters     GetViewsFilterArrayInput `pulumi:"filters"`
	// The OCID of a resource.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// Value must be `PRIVATE` when listing private views.
	Scope pulumi.StringPtrInput `pulumi:"scope"`
	// The state of a resource.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetViewsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetViewsArgs)(nil)).Elem()
}

// A collection of values returned by getViews.
type GetViewsResultOutput struct{ *pulumi.OutputState }

func (GetViewsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetViewsResult)(nil)).Elem()
}

func (o GetViewsResultOutput) ToGetViewsResultOutput() GetViewsResultOutput {
	return o
}

func (o GetViewsResultOutput) ToGetViewsResultOutputWithContext(ctx context.Context) GetViewsResultOutput {
	return o
}

// The OCID of the owning compartment.
func (o GetViewsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetViewsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The display name of the view.
func (o GetViewsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetViewsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetViewsResultOutput) Filters() GetViewsFilterArrayOutput {
	return o.ApplyT(func(v GetViewsResult) []GetViewsFilter { return v.Filters }).(GetViewsFilterArrayOutput)
}

// The OCID of the view.
func (o GetViewsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetViewsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

func (o GetViewsResultOutput) Scope() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetViewsResult) *string { return v.Scope }).(pulumi.StringPtrOutput)
}

// The current state of the resource.
func (o GetViewsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetViewsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The list of views.
func (o GetViewsResultOutput) Views() GetViewsViewArrayOutput {
	return o.ApplyT(func(v GetViewsResult) []GetViewsView { return v.Views }).(GetViewsViewArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetViewsResultOutput{})
}