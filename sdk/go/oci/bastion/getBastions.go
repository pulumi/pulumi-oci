// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package bastion

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Bastions in Oracle Cloud Infrastructure Bastion service.
//
// Retrieves a list of BastionSummary objects in a compartment. Bastions provide secured, public access to target resources in the cloud that you cannot otherwise reach from the internet.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Bastion"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Bastion.GetBastions(ctx, &bastion.GetBastionsArgs{
//				CompartmentId:         _var.Compartment_id,
//				BastionId:             pulumi.StringRef(oci_bastion_bastion.Test_bastion.Id),
//				BastionLifecycleState: pulumi.StringRef(_var.Bastion_bastion_lifecycle_state),
//				Name:                  pulumi.StringRef(_var.Bastion_name),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetBastions(ctx *pulumi.Context, args *GetBastionsArgs, opts ...pulumi.InvokeOption) (*GetBastionsResult, error) {
	var rv GetBastionsResult
	err := ctx.Invoke("oci:Bastion/getBastions:getBastions", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getBastions.
type GetBastionsArgs struct {
	// The unique identifier (OCID) of the bastion in which to list resources.
	BastionId *string `pulumi:"bastionId"`
	// A filter to return only resources their lifecycleState matches the given lifecycleState.
	BastionLifecycleState *string `pulumi:"bastionLifecycleState"`
	// The unique identifier (OCID) of the compartment in which to list resources.
	CompartmentId string              `pulumi:"compartmentId"`
	Filters       []GetBastionsFilter `pulumi:"filters"`
	// A filter to return only resources that match the entire name given.
	Name *string `pulumi:"name"`
}

// A collection of values returned by getBastions.
type GetBastionsResult struct {
	BastionId             *string `pulumi:"bastionId"`
	BastionLifecycleState *string `pulumi:"bastionLifecycleState"`
	// The list of bastions.
	Bastions []GetBastionsBastion `pulumi:"bastions"`
	// The unique identifier (OCID) of the compartment where the bastion is located.
	CompartmentId string              `pulumi:"compartmentId"`
	Filters       []GetBastionsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The name of the bastion, which can't be changed after creation.
	Name *string `pulumi:"name"`
}

func GetBastionsOutput(ctx *pulumi.Context, args GetBastionsOutputArgs, opts ...pulumi.InvokeOption) GetBastionsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetBastionsResult, error) {
			args := v.(GetBastionsArgs)
			r, err := GetBastions(ctx, &args, opts...)
			var s GetBastionsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetBastionsResultOutput)
}

// A collection of arguments for invoking getBastions.
type GetBastionsOutputArgs struct {
	// The unique identifier (OCID) of the bastion in which to list resources.
	BastionId pulumi.StringPtrInput `pulumi:"bastionId"`
	// A filter to return only resources their lifecycleState matches the given lifecycleState.
	BastionLifecycleState pulumi.StringPtrInput `pulumi:"bastionLifecycleState"`
	// The unique identifier (OCID) of the compartment in which to list resources.
	CompartmentId pulumi.StringInput          `pulumi:"compartmentId"`
	Filters       GetBastionsFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the entire name given.
	Name pulumi.StringPtrInput `pulumi:"name"`
}

func (GetBastionsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetBastionsArgs)(nil)).Elem()
}

// A collection of values returned by getBastions.
type GetBastionsResultOutput struct{ *pulumi.OutputState }

func (GetBastionsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetBastionsResult)(nil)).Elem()
}

func (o GetBastionsResultOutput) ToGetBastionsResultOutput() GetBastionsResultOutput {
	return o
}

func (o GetBastionsResultOutput) ToGetBastionsResultOutputWithContext(ctx context.Context) GetBastionsResultOutput {
	return o
}

func (o GetBastionsResultOutput) BastionId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetBastionsResult) *string { return v.BastionId }).(pulumi.StringPtrOutput)
}

func (o GetBastionsResultOutput) BastionLifecycleState() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetBastionsResult) *string { return v.BastionLifecycleState }).(pulumi.StringPtrOutput)
}

// The list of bastions.
func (o GetBastionsResultOutput) Bastions() GetBastionsBastionArrayOutput {
	return o.ApplyT(func(v GetBastionsResult) []GetBastionsBastion { return v.Bastions }).(GetBastionsBastionArrayOutput)
}

// The unique identifier (OCID) of the compartment where the bastion is located.
func (o GetBastionsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetBastionsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetBastionsResultOutput) Filters() GetBastionsFilterArrayOutput {
	return o.ApplyT(func(v GetBastionsResult) []GetBastionsFilter { return v.Filters }).(GetBastionsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetBastionsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetBastionsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The name of the bastion, which can't be changed after creation.
func (o GetBastionsResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetBastionsResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetBastionsResultOutput{})
}