// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Compartments in Oracle Cloud Infrastructure Identity service.
//
// Lists the compartments in a specified compartment. The members of the list
// returned depends on the values set for several parameters.
//
// With the exception of the tenancy (root compartment), the ListCompartments operation
// returns only the first-level child compartments in the parent compartment specified in
// `compartmentId`. The list does not include any subcompartments of the child
// compartments (grandchildren).
//
// The parameter `accessLevel` specifies whether to return only those compartments for which the
// requestor has INSPECT permissions on at least one resource directly
// or indirectly (the resource can be in a subcompartment).
//
// The parameter `compartmentIdInSubtree` applies only when you perform ListCompartments on the
// tenancy (root compartment). When set to true, the entire hierarchy of compartments can be returned.
// To get a full list of all compartments and subcompartments in the tenancy (root compartment),
// set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ANY.
//
// See [Where to Get the Tenancy's OCID and User's OCID](https://docs.cloud.oracle.com/iaas/Content/API/Concepts/apisigningkey.htm#five).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Identity"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Identity.GetCompartments(ctx, &identity.GetCompartmentsArgs{
//				CompartmentId:          _var.Compartment_id,
//				AccessLevel:            pulumi.StringRef(_var.Compartment_access_level),
//				CompartmentIdInSubtree: pulumi.BoolRef(_var.Compartment_compartment_id_in_subtree),
//				Name:                   pulumi.StringRef(_var.Compartment_name),
//				State:                  pulumi.StringRef(_var.Compartment_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetCompartments(ctx *pulumi.Context, args *GetCompartmentsArgs, opts ...pulumi.InvokeOption) (*GetCompartmentsResult, error) {
	var rv GetCompartmentsResult
	err := ctx.Invoke("oci:Identity/getCompartments:getCompartments", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCompartments.
type GetCompartmentsArgs struct {
	// Valid values are `ANY` and `ACCESSIBLE`. Default is `ANY`. Setting this to `ACCESSIBLE` returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). For the compartments on which the user indirectly has INSPECT permissions, a restricted set of fields is returned.
	AccessLevel *string `pulumi:"accessLevel"`
	// The OCID of the compartment (remember that the tenancy is simply the root compartment).
	CompartmentId string `pulumi:"compartmentId"`
	// Default is false. Can only be set to true when performing ListCompartments on the tenancy (root compartment). When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
	CompartmentIdInSubtree *bool                   `pulumi:"compartmentIdInSubtree"`
	Filters                []GetCompartmentsFilter `pulumi:"filters"`
	// A filter to only return resources that match the given name exactly.
	Name *string `pulumi:"name"`
	// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getCompartments.
type GetCompartmentsResult struct {
	AccessLevel *string `pulumi:"accessLevel"`
	// The OCID of the parent compartment containing the compartment.
	CompartmentId          string `pulumi:"compartmentId"`
	CompartmentIdInSubtree *bool  `pulumi:"compartmentIdInSubtree"`
	// The list of compartments.
	Compartments []GetCompartmentsCompartment `pulumi:"compartments"`
	Filters      []GetCompartmentsFilter      `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The name you assign to the compartment during creation. The name must be unique across all compartments in the parent. Avoid entering confidential information.
	Name *string `pulumi:"name"`
	// The compartment's current state.
	State *string `pulumi:"state"`
}

func GetCompartmentsOutput(ctx *pulumi.Context, args GetCompartmentsOutputArgs, opts ...pulumi.InvokeOption) GetCompartmentsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetCompartmentsResult, error) {
			args := v.(GetCompartmentsArgs)
			r, err := GetCompartments(ctx, &args, opts...)
			var s GetCompartmentsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetCompartmentsResultOutput)
}

// A collection of arguments for invoking getCompartments.
type GetCompartmentsOutputArgs struct {
	// Valid values are `ANY` and `ACCESSIBLE`. Default is `ANY`. Setting this to `ACCESSIBLE` returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). For the compartments on which the user indirectly has INSPECT permissions, a restricted set of fields is returned.
	AccessLevel pulumi.StringPtrInput `pulumi:"accessLevel"`
	// The OCID of the compartment (remember that the tenancy is simply the root compartment).
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Default is false. Can only be set to true when performing ListCompartments on the tenancy (root compartment). When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
	CompartmentIdInSubtree pulumi.BoolPtrInput             `pulumi:"compartmentIdInSubtree"`
	Filters                GetCompartmentsFilterArrayInput `pulumi:"filters"`
	// A filter to only return resources that match the given name exactly.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// A filter to only return resources that match the given lifecycle state.  The state value is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetCompartmentsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCompartmentsArgs)(nil)).Elem()
}

// A collection of values returned by getCompartments.
type GetCompartmentsResultOutput struct{ *pulumi.OutputState }

func (GetCompartmentsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCompartmentsResult)(nil)).Elem()
}

func (o GetCompartmentsResultOutput) ToGetCompartmentsResultOutput() GetCompartmentsResultOutput {
	return o
}

func (o GetCompartmentsResultOutput) ToGetCompartmentsResultOutputWithContext(ctx context.Context) GetCompartmentsResultOutput {
	return o
}

func (o GetCompartmentsResultOutput) AccessLevel() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCompartmentsResult) *string { return v.AccessLevel }).(pulumi.StringPtrOutput)
}

// The OCID of the parent compartment containing the compartment.
func (o GetCompartmentsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetCompartmentsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetCompartmentsResultOutput) CompartmentIdInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetCompartmentsResult) *bool { return v.CompartmentIdInSubtree }).(pulumi.BoolPtrOutput)
}

// The list of compartments.
func (o GetCompartmentsResultOutput) Compartments() GetCompartmentsCompartmentArrayOutput {
	return o.ApplyT(func(v GetCompartmentsResult) []GetCompartmentsCompartment { return v.Compartments }).(GetCompartmentsCompartmentArrayOutput)
}

func (o GetCompartmentsResultOutput) Filters() GetCompartmentsFilterArrayOutput {
	return o.ApplyT(func(v GetCompartmentsResult) []GetCompartmentsFilter { return v.Filters }).(GetCompartmentsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetCompartmentsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetCompartmentsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The name you assign to the compartment during creation. The name must be unique across all compartments in the parent. Avoid entering confidential information.
func (o GetCompartmentsResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCompartmentsResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The compartment's current state.
func (o GetCompartmentsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCompartmentsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetCompartmentsResultOutput{})
}