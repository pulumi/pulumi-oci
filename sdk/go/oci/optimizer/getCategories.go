// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package optimizer

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Categories in Oracle Cloud Infrastructure Optimizer service.
//
// Lists the supported Cloud Advisor categories.
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
//			_, err := Optimizer.GetCategories(ctx, &optimizer.GetCategoriesArgs{
//				CompartmentId:          _var.Compartment_id,
//				CompartmentIdInSubtree: _var.Category_compartment_id_in_subtree,
//				ChildTenancyIds:        _var.Category_child_tenancy_ids,
//				IncludeOrganization:    pulumi.BoolRef(_var.Category_include_organization),
//				Name:                   pulumi.StringRef(_var.Category_name),
//				State:                  pulumi.StringRef(_var.Category_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetCategories(ctx *pulumi.Context, args *GetCategoriesArgs, opts ...pulumi.InvokeOption) (*GetCategoriesResult, error) {
	var rv GetCategoriesResult
	err := ctx.Invoke("oci:Optimizer/getCategories:getCategories", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCategories.
type GetCategoriesArgs struct {
	// A list of child tenancies for which the respective data will be returned. Please note that  the parent tenancy id can also be included in this list. For example, if there is a parent P with two children A and B, to return results of only parent P and child A, this list should be populated with  tenancy id of parent P and child A.
	ChildTenancyIds []string `pulumi:"childTenancyIds"`
	// The OCID of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
	CompartmentIdInSubtree bool                  `pulumi:"compartmentIdInSubtree"`
	Filters                []GetCategoriesFilter `pulumi:"filters"`
	// When set to true, the data for all child tenancies including the parent is returned. That is, if  there is an organization with parent P and children A and B, to return the data for the parent P, child  A and child B, this parameter value should be set to true.
	IncludeOrganization *bool `pulumi:"includeOrganization"`
	// Optional. A filter that returns results that match the name specified.
	Name *string `pulumi:"name"`
	// A filter that returns results that match the lifecycle state specified.
	State *string `pulumi:"state"`
}

// A collection of values returned by getCategories.
type GetCategoriesResult struct {
	// The list of category_collection.
	CategoryCollections []GetCategoriesCategoryCollection `pulumi:"categoryCollections"`
	ChildTenancyIds     []string                          `pulumi:"childTenancyIds"`
	// The OCID of the tenancy. The tenancy is the root compartment.
	CompartmentId          string                `pulumi:"compartmentId"`
	CompartmentIdInSubtree bool                  `pulumi:"compartmentIdInSubtree"`
	Filters                []GetCategoriesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                  string `pulumi:"id"`
	IncludeOrganization *bool  `pulumi:"includeOrganization"`
	// The name assigned to the category.
	Name *string `pulumi:"name"`
	// The category's current state.
	State *string `pulumi:"state"`
}

func GetCategoriesOutput(ctx *pulumi.Context, args GetCategoriesOutputArgs, opts ...pulumi.InvokeOption) GetCategoriesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetCategoriesResult, error) {
			args := v.(GetCategoriesArgs)
			r, err := GetCategories(ctx, &args, opts...)
			var s GetCategoriesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetCategoriesResultOutput)
}

// A collection of arguments for invoking getCategories.
type GetCategoriesOutputArgs struct {
	// A list of child tenancies for which the respective data will be returned. Please note that  the parent tenancy id can also be included in this list. For example, if there is a parent P with two children A and B, to return results of only parent P and child A, this list should be populated with  tenancy id of parent P and child A.
	ChildTenancyIds pulumi.StringArrayInput `pulumi:"childTenancyIds"`
	// The OCID of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned depending on the the setting of `accessLevel`.
	CompartmentIdInSubtree pulumi.BoolInput              `pulumi:"compartmentIdInSubtree"`
	Filters                GetCategoriesFilterArrayInput `pulumi:"filters"`
	// When set to true, the data for all child tenancies including the parent is returned. That is, if  there is an organization with parent P and children A and B, to return the data for the parent P, child  A and child B, this parameter value should be set to true.
	IncludeOrganization pulumi.BoolPtrInput `pulumi:"includeOrganization"`
	// Optional. A filter that returns results that match the name specified.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// A filter that returns results that match the lifecycle state specified.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetCategoriesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCategoriesArgs)(nil)).Elem()
}

// A collection of values returned by getCategories.
type GetCategoriesResultOutput struct{ *pulumi.OutputState }

func (GetCategoriesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCategoriesResult)(nil)).Elem()
}

func (o GetCategoriesResultOutput) ToGetCategoriesResultOutput() GetCategoriesResultOutput {
	return o
}

func (o GetCategoriesResultOutput) ToGetCategoriesResultOutputWithContext(ctx context.Context) GetCategoriesResultOutput {
	return o
}

// The list of category_collection.
func (o GetCategoriesResultOutput) CategoryCollections() GetCategoriesCategoryCollectionArrayOutput {
	return o.ApplyT(func(v GetCategoriesResult) []GetCategoriesCategoryCollection { return v.CategoryCollections }).(GetCategoriesCategoryCollectionArrayOutput)
}

func (o GetCategoriesResultOutput) ChildTenancyIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetCategoriesResult) []string { return v.ChildTenancyIds }).(pulumi.StringArrayOutput)
}

// The OCID of the tenancy. The tenancy is the root compartment.
func (o GetCategoriesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetCategoriesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetCategoriesResultOutput) CompartmentIdInSubtree() pulumi.BoolOutput {
	return o.ApplyT(func(v GetCategoriesResult) bool { return v.CompartmentIdInSubtree }).(pulumi.BoolOutput)
}

func (o GetCategoriesResultOutput) Filters() GetCategoriesFilterArrayOutput {
	return o.ApplyT(func(v GetCategoriesResult) []GetCategoriesFilter { return v.Filters }).(GetCategoriesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetCategoriesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetCategoriesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetCategoriesResultOutput) IncludeOrganization() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetCategoriesResult) *bool { return v.IncludeOrganization }).(pulumi.BoolPtrOutput)
}

// The name assigned to the category.
func (o GetCategoriesResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCategoriesResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The category's current state.
func (o GetCategoriesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCategoriesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetCategoriesResultOutput{})
}